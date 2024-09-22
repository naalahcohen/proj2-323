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

typedef struct header{
	size_t payload_size;
    const char* file;
    long long line;
    bool valid; 
}header;

std::map<uintptr_t, header> bigmap;
std::map<std::string, size_t> heavymap;

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    size_t total_size = sizeof(header) + 12 + 4 + sz + 4;
    if(SIZE_MAX - sz < sizeof(header) + 12 + 8){
        global_nfail++;
        global_fail_size += sz;
        return nullptr;
    }

    header* metadata = (header*) base_malloc(total_size);
    // (16 - x%16)
    if (metadata == NULL) {
        global_nfail++;
        global_fail_size += sz;
        return nullptr;
    }

    metadata->payload_size = sz;
    metadata->valid = true;
    metadata->file = file;
    metadata->line = line;
    //do a loop and can add up to 8 bytes at once, make it so that is a multiple of 8 bigger 200
    char* underflow_canary = (char*) (metadata + 1);
    *(uint32_t*)underflow_canary = 0xDEADBEEF;

    void* ptr = (void*) (underflow_canary + 4 + 12);  // skip canary and padding

    char* overflow_canary = (char*)ptr + sz;
    *(uint32_t*)overflow_canary = 0xDEADBEEF;

    uintptr_t key = reinterpret_cast<uintptr_t>(ptr);
    bigmap[key] = *metadata;

    global_nactive++;
    global_active_size += sz;
    global_ntotal++;
    global_total_size += sz;

    std::ostringstream oss;
    oss << file << ":" << line;
    std::string str = oss.str();

    heavymap[str] += sz; 

    uintptr_t start = reinterpret_cast<uintptr_t>(metadata);
    uintptr_t end = reinterpret_cast<uintptr_t>(overflow_canary + 4);

    if (start < global_heap_min) {
        global_heap_min = start;
    }
    if (end > global_heap_max) {
        global_heap_max = end;
    }

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


/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to dmalloc_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.
void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    if (ptr == nullptr) {
        return;
    }

    uintptr_t ptr_key = reinterpret_cast<uintptr_t>(ptr);
    bool found_in_heap = false;
    bool is_start_of_allocation = false;

    // Iterate through all allocations to find if the pointer is within any allocation block
    for (const auto& entry : bigmap) {
        uintptr_t block_start = entry.first;
        size_t block_size = entry.second.payload_size;

        if (ptr_key >= block_start && ptr_key < block_start + block_size) {
            found_in_heap = true;
            if (ptr_key == block_start) {
                is_start_of_allocation = true;
            }
            break;
        }
    }

    if (!found_in_heap) {
        std::cerr << "MEMORY BUG: " << file << ":" << line 
                  << ": invalid free of pointer " << ptr 
                  << ", not in heap" << std::endl;
        return;
    }

    if (!is_start_of_allocation) {
        std::cerr << "MEMORY BUG: " << file << ":" << line 
                  << ": invalid free of pointer " << ptr 
                  << ", not allocated" << std::endl;
        return;
    }

    // Check for double free
    if (!isvalid(bigmap, ptr)) {
        std::cerr << "MEMORY BUG: " << file << ":" << line
                  << ": invalid free of pointer " << ptr
                  << ", double free" << std::endl;
        return;
    }

    // Check underflow canary
    char* underflow_canary = (char*) (ptr_key - 12 - 4);
    if (*(uint32_t*)underflow_canary != 0xDEADBEEF) {
        std::cerr << "MEMORY BUG: " << file << ":" << line 
                  << ": detected wild write before allocated memory block " << ptr 
                  << std::endl;
        return;
    }

    // Check overflow canary
    char* overflow_canary = (char*) (ptr_key + bigmap[ptr_key].payload_size);
    if (*(uint32_t*)overflow_canary != 0xDEADBEEF) {
        std::cerr << "MEMORY BUG: " << file << ":" << line 
                  << ": detected wild write during free of pointer " << ptr 
                  << std::endl;
        return;
    }

    // Perform the free
    base_free(ptr);

    // Mark the block as freed
    bigmap[ptr_key].valid = false;

    // Update global statistics
    global_nactive--;
    global_active_size -= bigmap[ptr_key].payload_size;
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
    for (const auto& entry : bigmap) {
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