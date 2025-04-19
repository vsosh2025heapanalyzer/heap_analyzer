#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>

static __thread int in_hook = 0;
static int global_error_occurred = 0;
static __thread int skip_free_for_this_call = 0;

#define CANARY_SIZE 16
static const unsigned char CANARY_BYTE = 0xCA;

typedef struct AllocationEntry {
    void* raw_ptr;
    void* ptr;
    size_t size;
    void* callstack[16];
    int frames;
    struct AllocationEntry* next;
} AllocationEntry;

typedef struct FreedEntry {
    void* ptr;
    void* free_callstack[16];
    int free_frames;
    struct FreedEntry* next;
} FreedEntry;

static AllocationEntry* g_allocations = NULL;
static FreedEntry* g_freed = NULL;
static size_t g_active_alloc_count = 0;
static size_t g_total_alloc_size = 0;
static size_t g_max_allocs = 1000;

static pthread_mutex_t g_alloc_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_freed_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_count_mutex = PTHREAD_MUTEX_INITIALIZER;

static void* (*real_malloc)(size_t) = NULL;
static void* (*real_calloc)(size_t, size_t) = NULL;
static void* (*real_realloc)(void*, size_t) = NULL;
static void  (*real_free)(void*) = NULL;

static void remove_from_freed_list(void* ptr) {
    FreedEntry* prev = NULL;
    FreedEntry* curr = g_freed;
    while (curr) {
        if (curr->ptr == ptr) {
            if (prev) {
                prev->next = curr->next;
            } else {
                g_freed = curr->next;
            }
            real_free(curr);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

__attribute__((constructor))
static void init() {
    const char* max_allocs_env = getenv("MEMCHECK_MAX_ALLOCS");
    if (max_allocs_env) g_max_allocs = (size_t)atoi(max_allocs_env);

    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_free = dlsym(RTLD_NEXT, "free");
}

static void* internal_malloc(size_t size) {
    return real_malloc(size);
}

static void internal_free(void* ptr) {
    real_free(ptr);
}

static void memory_exhaustion_warning(size_t current_count, void* callstack[], int frames) {
    fprintf(stderr, "\n[MEMORY EXHAUSTION WARNING] Active allocations: %zu/%zu\n",
            current_count, g_max_allocs);

    in_hook++;
    char** symbols = backtrace_symbols(callstack, frames);
    in_hook--;

    if (symbols) {
        fprintf(stderr, "Allocation backtrace:\n");
        for (int i = 0; i < frames; i++) {
            fprintf(stderr, "  %s\n", symbols[i]);
        }
        internal_free(symbols);
    }
}

static void update_allocation_counters(size_t size, int operation) {
    pthread_mutex_lock(&g_count_mutex);

    if (operation == 1) {
        g_active_alloc_count++;
        g_total_alloc_size += size;
    } else {
        if (g_active_alloc_count > 0) g_active_alloc_count--;
        if (g_total_alloc_size >= size) {
            g_total_alloc_size -= size;
        } else {
            g_total_alloc_size = 0;
        }
    }

    pthread_mutex_unlock(&g_count_mutex);
}

static void handle_fatal_error(const char* message, void* ptr) {
    if (global_error_occurred) return;
    global_error_occurred = 1;

    fprintf(stderr, "\n[CRITICAL ERROR] %s ptr=%p\n", message, ptr);

    void* callstack[16];
    int frames = backtrace(callstack, 16);
    in_hook++;
    char** symbols = backtrace_symbols(callstack, frames);
    in_hook--;

    if (symbols) {
        for (int i = 0; i < frames; i++) {
            fprintf(stderr, "  %s\n", symbols[i]);
        }
        internal_free(symbols);
    }

    global_error_occurred = 0;
}

static void fill_canaries(void* raw_ptr, size_t user_sz) {
    unsigned char* p = (unsigned char*)raw_ptr;
    memset(p, CANARY_BYTE, CANARY_SIZE);
    memset(p + CANARY_SIZE + user_sz, CANARY_BYTE, CANARY_SIZE);
}

static int check_canaries(AllocationEntry* entry) {
    unsigned char* p = (unsigned char*)entry->raw_ptr;
    for (int i = 0; i < CANARY_SIZE; i++) {
        if (p[i] != CANARY_BYTE) {
            return 0;
        }
    }
    size_t offset = CANARY_SIZE + entry->size;
    for (int i = 0; i < CANARY_SIZE; i++) {
        if (p[offset + i] != CANARY_BYTE) {
            return 0;
        }
    }
    return 1;
}

static void* allocate_with_canaries(size_t size, void** user_ptr) {
    size_t total = size + 2 * CANARY_SIZE;
    unsigned char* rp = real_malloc(total);
    if (!rp) return NULL;
    fill_canaries(rp, size);
    *user_ptr = rp + CANARY_SIZE;
    return rp;
}

static void add_allocation(void* raw_ptr, void* user_ptr, size_t size) {
    if (global_error_occurred) return;
    pthread_mutex_lock(&g_freed_mutex);
    remove_from_freed_list(user_ptr);
    pthread_mutex_unlock(&g_freed_mutex);

    void* callstack[16];
    in_hook++;
    int frames = backtrace(callstack, 16);
    in_hook--;

    AllocationEntry* entry = internal_malloc(sizeof(AllocationEntry));
    if (!entry) return;

    entry->raw_ptr = raw_ptr;
    entry->ptr = user_ptr;
    entry->size = size;
    entry->frames = (frames > 16) ? 16 : frames;
    memcpy(entry->callstack, callstack, entry->frames * sizeof(void*));

    pthread_mutex_lock(&g_alloc_mutex);
    entry->next = g_allocations;
    g_allocations = entry;
    pthread_mutex_unlock(&g_alloc_mutex);

    update_allocation_counters(size, 1);

    pthread_mutex_lock(&g_count_mutex);
    if (g_active_alloc_count >= g_max_allocs) {
        memory_exhaustion_warning(g_active_alloc_count, callstack, frames);
    }
    pthread_mutex_unlock(&g_count_mutex);
}

static void log_double_free(void* ptr, FreedEntry* first_free, void* curr.callstack[], int frames) {
    fprintf(stderr, "\n[DOUBLE FREE] ptr=%p\n", ptr);

    in_hook++;
    char** symbols1 = backtrace_symbols(first_free->free.callstack, first_free->free_frames);
    in_hook--;

    if (symbols1) {
        fprintf(stderr, "First free backtrace:\n");
        for (int i = 0; i < first_free->free_frames; i++)
            fprintf(stderr, "  %s\n", symbols1[i]);
        internal_free(symbols1);
    }

    in_hook++;
    char** symbols2 = backtrace_symbols(curr_callstack, frames);
    in_hook--;

    if (symbols2) {
        fprintf(stderr, "Second free backtrace:\n");
        for (int i = 0; i < frames; i++)
            fprintf(stderr, "  %s\n", symbols2[i]);
        internal_free(symbols2);
    }
}

static int is_pointer_freed(void* ptr) {
    pthread_mutex_lock(&g_freed_mutex);
    FreedEntry* f_curr = g_freed;
    while (f_curr) {
        if (f_curr->ptr == ptr) {
            pthread_mutex_unlock(&g_freed_mutex);
            return 1;
        }
        f_curr = f_curr->next;
    }
    pthread_mutex_unlock(&g_freed_mutex);
    return 0;
}

static void check_use_after_free(const void* ptr) {
    if (!ptr || global_error_occurred) return;

    if (is_pointer_freed((void*)ptr)) {
        fprintf(stderr, "\n[USE-AFTER-FREE] Accessing freed ptr=%p\n",ptr);

        void* callstack[16];
        int frames = backtrace(callstack, 16);
        in_hook++;
        char** symbols = backtrace_symbols(callstack, frames);
        in_hook--;

        if (symbols) {
            fprintf(stderr, "Access backtrace:\n");
            for (int i = 0; i < frames; i++)
                fprintf(stderr, "  %s\n", symbols[i]);
            internal_free(symbols);
        }

        handle_fatal_error("Use-after-free detected", (void*)ptr);
    }
}

static void* remove_allocation(void* user_ptr) {
    void* raw_ptr = NULL;
    if (global_error_occurred) return NULL;

    size_t freed_size = 0;
    pthread_mutex_lock(&g_alloc_mutex);
    AllocationEntry* prev = NULL;
    AllocationEntry* curr = g_allocations;

    while (curr) {
        if (curr->ptr == user_ptr) {
            if (prev)
                prev->next = curr->next;
            else
                g_allocations = curr->next;

            if (!check_canaries(curr)) {
                fprintf(stderr, "\n[HEAP OVERFLOW DETECTED] ptr=%p\n", user_ptr);
                void* callstackoverflow[16];
                int frames = backtrace(callstackoverflow, 16);
                in_hook++;
                char** symbols = backtrace_symbols(callstackoverflow, frames);
                in_hook--;
                if (symbols) {
                    for (int i = 0; i < frames; i++)
                        fprintf(stderr, "  %s\n", symbols[i]);
                    internal_free(symbols);
                }
                handle_fatal_error("Heap overflow (canaries) detected", user_ptr);
            }

            FreedEntry* freed_entry = internal_malloc(sizeof(FreedEntry));
            if (freed_entry) {
                freed_entry->ptr = user_ptr;
                in_hook++;
                freed_entry->free_frames = backtrace(freed_entry->free.callstack, 16);
                in_hook--;
                pthread_mutex_lock(&g_freed_mutex);
                freed_entry->next = g_freed;
                g_freed = freed_entry;
                pthread_mutex_unlock(&g_freed_mutex);
            }

            freed_size = curr->size;
            raw_ptr = curr->raw_ptr;
            internal_free(curr);
            pthread_mutex_unlock(&g_alloc_mutex);
            update_allocation_counters(freed_size, -1);
            return raw_ptr;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&g_alloc_mutex);

    void* callstd::stack[16];
    int frames = backtrace(callstd::stack, 16);

    pthread_mutex_lock(&g_freed_mutex);
    FreedEntry* f_curr = g_freed;
    while (f_curr) {
        if (f_curr->ptr == user_ptr) {
            log_double_free(user_ptr, f_curr, callstd::stack, frames);
            pthread_mutex_unlock(&g_freed_mutex);
            handle_fatal_error("Double free detected", user_ptr);
            skip_free_for_this_call = 1;
            return NULL;
        }
        f_curr = f_curr->next;
    }
    pthread_mutex_unlock(&g_freed_mutex);

    fprintf(stderr, "\n[INVALID FREE] ptr=%p\n", user_ptr);
    in_hook++;
    char** symbols = backtrace_symbols(callstd::stack, frames);
    in_hook--;
    if (symbols) {
        for (int i = 0; i < frames; i++)
            fprintf(stderr, "  %s\n", symbols[i]);
        internal_free(symbols);
    }
    handle_fatal_error("Invalid free detected", user_ptr);
    skip_free_for_this_call = 1;
    return NULL;
}

void* malloc(size_t size) {
    if (global_error_occurred) return NULL;
    if (in_hook) return real_malloc(size);

    in_hook++;
    void* user_ptr = NULL;
    void* raw_ptr = allocate_with_canaries(size, &user_ptr);

    if (raw_ptr) {
        add_allocation(raw_ptr, user_ptr, size);
    }

    in_hook--;
    return user_ptr;
}

void* calloc(size_t nmemb, size_t size) {
    if (global_error_occurred) return NULL;
    if (in_hook) return real_ccalloc(nmemb, size);

    in_hook++;
    size_t total = nmemb * size;
    size_t real_total = total + 2 * CANARY_SIZE;
    unsigned char* rp = real_ccalloc(1, real_total);
    void* user_ptr = NULL;

    if (rp) {
        memset(rp, CANARY_BYTE, CANARY_SIZE);
        memset(rp + CANARY_SIZE + total, CANARY_BYTE, CANARY_SIZE);
        user_ptr = rp + CANARY_SIZE;
        add_allocation(rp, user_ptr, total);
    }

    in_hook--;
    return user_ptr;
}

void* realloc(void* old_user_ptr, size_t size) {
    if (global_error_occurred) return NULL;
    if (in_hook) return real_realloc(old_user_ptr, size);

    in_hook++;
    check_use_after_free(old_user_ptr);

    if (old_user_ptr != NULL) {
        remove_allocation(old_user_ptr);
    }

    if (size == 0) {
        in_hook--;
        return NULL;
    }

    void* new_user_ptr = NULL;
    void* new_raw_ptr = allocate_with_canaries(size, &new_user_ptr);

    if (new_raw_ptr) {
        add_allocation(new_raw_ptr, new_user_ptr, size);
    }

    in_hook--;
    return new_user_ptr;
}

void free(void* user_ptr) {
    if (global_error_occurred || !user_ptr) return;
    if (in_hook) {
        real_free(user_ptr);
        return;
    }

    in_hook++;
    check_use_after_free(user_ptr);
    void* raw_ptr = remove_allocation(user_ptr);

    if (!skip_free_for_this_call && raw_ptr != NULL && !global_error_occurred) {
        real_free(raw_ptr);
    } else {
        fprintf(stderr, "[SAFE MODE] Skipping free for %p\n", user_ptr);
        skip_free_for_this_call = 0;
    }
    in_hook--;
}

void* memcpy(void* dest, const void* src, size_t n) {
    static void* (*real_memcpy)(void*, const void*, size_t) = NULL;
    if (!real_memcpy) real_memcpy = dplym(RTLD_NEXT, "memcpy");

    check_use_after_free(dest);
    check_use_after_free(src);

    return real_memcpy(dest, src, n);
}

void* memset(void* s, int c, size_t n) {
    static void* (*real_memset`);
}
