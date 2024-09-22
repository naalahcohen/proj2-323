#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <map>
#include <iostream> 
#include <cstdint>
#include <sstream>  
#include <vector>  
#include <algorithm> 




// 0-32  
//create global variables of everything in statistics struct 
//set them to the variables in the struct 

static unsigned long long global_nactive = 0;        
static unsigned long long global_active_size =0;  
static unsigned long long global_ntotal = 0;          
static unsigned long long global_total_size = 0;      
static unsigned long long global_nfail = 0;           
static unsigned long long global_fail_size = 0;       
static uintptr_t global_heap_min = UINTPTR_MAX;                 
static uintptr_t global_heap_max = 0;     
constexpr size_t CANARY_SIZE = 200;

typedef struct header{
	size_t payload_size;
    const char* file;
    long long line;
    bool valid; 
}header;

std::map<uintptr_t, header> activemap;
std::map<uintptr_t, header> freemap;
std::map<std::string, size_t> heavymap;

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    // Define the canary size to be at least 200 bytes and a multiple of 8
    size_t canary_size = 200;
    if (canary_size % 8 != 0) {
        canary_size += 8 - (canary_size % 8);  // Ensure it's a multiple of 8
    }

    // Calculate the total size needed for the allocation, including canaries and padding
    size_t total_size = sizeof(header) + CANARY_SIZE + sz + CANARY_SIZE;
    
    if (SIZE_MAX - sz < sizeof(header) + 12 + 2 * canary_size) {
        global_nfail++;
        global_fail_size += sz;
        return nullptr;
    }

    // Allocate memory including space for header, canaries, padding, and payload
    header* metadata = (header*) base_malloc(total_size);
    
    if (metadata == NULL) {
        global_nfail++;
        global_fail_size += sz;
        return nullptr;
    }

    // Initialize the metadata
    metadata->payload_size = sz;
    metadata->valid = true;
    metadata->file = file;
    metadata->line = line;

    // Set up the underflow canary
    char* underflow_canary = (char*) (metadata + 1);
    uint64_t canary_value = 0xDEADBEEFDEADBEEF;
    
    for (size_t i = 0; i < CANARY_SIZE; i += 8) {
        *(uint64_t*)(underflow_canary + i) = canary_value;
    }

    // Set the pointer to the start of the payload, skipping the canary and padding
    void* ptr = (void*) (underflow_canary + CANARY_SIZE);
    
    // Set up the overflow canary
    char* overflow_canary = (char*)ptr + sz;
    
    for (size_t i = 0; i < CANARY_SIZE; i += 8) {
        *(uint64_t*)(overflow_canary + i) = canary_value;
    }

    // Store metadata in the map
    uintptr_t key = reinterpret_cast<uintptr_t>(ptr);
    activemap[key] = *metadata;

    // Update global tracking variables
    global_nactive++;
    global_active_size += sz;
    global_ntotal++;
    global_total_size += sz;

    std::ostringstream oss;
    oss << file << ":" << line;
    std::string str = oss.str();

    heavymap[str] += sz; 

    uintptr_t start = reinterpret_cast<uintptr_t>(metadata);
    uintptr_t end = reinterpret_cast<uintptr_t>(overflow_canary + canary_size);

    if (start < global_heap_min) {
        global_heap_min = start;
    }
    if (end > global_heap_max) {
        global_heap_max = end;
    }
    //std::cout << "Allocated: " << key << " (pointer: " << ptr << ")" << std::endl;

    return ptr;
}

bool isvalid(const std::map<uintptr_t, header>& local_bigmap, void* ptr) {
    uintptr_t key = reinterpret_cast<uintptr_t>(ptr);
    auto it = local_bigmap.find(key);  
    if (it != local_bigmap.end()) {
        return it->second.valid;  
    }
    return false; 
}

// bool inmap(const std::map<unintptr_t, header>& local_bigmap, void*ptr){
//     uintptr_t ptr_key = reinterpret_cast<uintptr_t>(ptr);
//     for (const auto& entry : local_bigmap) {
//         uintptr_t block_start = entry.first;
//         size_t block_size = entry.second.payload_size;
//         if (ptr_key >= block_start && ptr_key < block_start + block_size) {
//             return true; 
//         }
//     }
//     return false;
// }



/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to dmalloc_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.
void dmalloc_free(void* ptr, const char* file, long line) {
    if (ptr == nullptr) {
        return;
    }

    uintptr_t ptr_key = reinterpret_cast<uintptr_t>(ptr);
    //std::cout << "Free Request: " << ptr_key << " (pointer: " << ptr << ")" << std::endl;
    if (ptr_key < global_heap_min || ptr_key > global_heap_max) {
            std::cerr << "MEMORY BUG: " << file << ":" << line 
                      << ": invalid free of pointer " << ptr 
                      << ", not in heap" << std::endl;
        
    } 
    auto active_it = activemap.find(ptr_key);
    if (active_it == activemap.end()) {
      // Check if it’s a double free
        if (freemap.find(ptr_key) != freemap.end()) {
            std::cerr << "MEMORY BUG: " << file << ":" << line
                      << ": invalid free of pointer " << ptr
                      << ", double free" << std::endl;
            return;
        }
        for (const auto& entry : activemap) {
            uintptr_t block_start = entry.first;
            size_t block_size = entry.second.payload_size;

            if (ptr_key > block_start && ptr_key < block_start + block_size) {
                size_t offset = ptr_key - block_start;
                std::cerr << "MEMORY BUG: " << file << ":" << line 
                        << ": invalid free of pointer " << ptr 
                        << ", not allocated" << std::endl;
                std::cerr << "  " << entry.second.file << ":" << entry.second.line 
                        << ": " << ptr 
                        << " is " << offset << " bytes inside a " 
                        << block_size << " byte region allocated here" << std::endl;
                return;
            }
        }
        std::cerr << "MEMORY BUG: " << file << ":" << line 
                      << ": invalid free of pointer " << ptr 
                      << ", not allocated" << std::endl;
        return;
    }

    char* underflow_canary = (char*)ptr - CANARY_SIZE;
    for (size_t i = 0; i < CANARY_SIZE; i += 8) {
        if (*(uint64_t*)(underflow_canary + i) != 0xDEADBEEFDEADBEEF) {
            std::cerr << "MEMORY BUG: " << file << ":" << line 
                      << ": detected wild write during free of pointer " << ptr 
                      << std::endl;
            return;
        }
    }

    char* overflow_canary = (char*)ptr + active_it->second.payload_size;
    for (size_t i = 0; i < CANARY_SIZE; i += 8) {
        if (*(uint64_t*)(overflow_canary + i) != 0xDEADBEEFDEADBEEF) {
            std::cerr << "MEMORY BUG: " << file << ":" << line 
                      << ": detected wild write during free of pointer " << ptr 
                      << std::endl;
            return;
        }
    }

    //std::cout << "Moving from active to free map: " << ptr_key << std::endl;
    freemap[ptr_key] = active_it->second;
    activemap.erase(active_it);

    base_free((char*)ptr - sizeof(header) - CANARY_SIZE);

    global_nactive--;
    global_active_size -= freemap[ptr_key].payload_size;

    //std::cout << "Active Map Size: " << activemap.size() << std::endl;
    //std::cout << "Free Map Size: " << freemap.size() << std::endl;
}





/// dmalloc_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    if (nmemb == 0 || sz == 0) {
        return dmalloc_malloc(1, file, line);  
    }

    if (sz > SIZE_MAX / nmemb) {
        global_nfail++;
        global_fail_size += nmemb * sz;  
        return nullptr;
    }

    size_t total = nmemb * sz;
    void* ptr = dmalloc_malloc(total, file, line);
    if (ptr) {
        memset(ptr, 0, total);
    } 
    else {
        global_nfail++;
        global_fail_size += total;
    }
    return ptr;
}


/// dmalloc_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void dmalloc_get_statistics(dmalloc_statistics* stats) {
    memset(stats, 255, sizeof(dmalloc_statistics));
    stats->nactive = global_nactive;
    stats->active_size = global_active_size; 
    stats->ntotal = global_ntotal;   
    stats->total_size = global_total_size;   
    stats->nfail = global_nfail;  
    stats->fail_size = global_fail_size;    
    stats->heap_min = global_heap_min;   
    stats->heap_max = global_heap_max;                
}


/// dmalloc_print_statistics()
///    Print the current memory statistics.

void dmalloc_print_statistics() {
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// dmalloc_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void dmalloc_print_leak_report() {
    for (const auto& entry : activemap) {
        const uintptr_t& key = entry.first;
        const header& value = entry.second;
        if (value.valid) {
            std::cout << "LEAK CHECK: " << value.file << ":" << value.line 
                      << ": allocated object " << static_cast<void*>(reinterpret_cast<void*>(key)) 
                      << " with size " << value.payload_size << std::endl;
        }
    }
}



/// dmalloc_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void dmalloc_print_heavy_hitter_report() {
    // size_t total_size = global_total_size;  

    // std::vector<std::pair<std::string, size_t>> heavy_hitters(heavymap.begin(), heavymap.end());
    // sort(heavyhitters.begin(), heavyhitters.end()); 

}

//divide size of how many bytes youve ever allocated at that line by total_sizde (which is kept track of in statistcs)
// 