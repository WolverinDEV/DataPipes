#include "pipes/allocator.h"

#include <atomic>
#include <cassert>
#include <cstring>
#include <string>
#include <cmath>
#include <sys/mman.h>

using namespace std;
using namespace pipes;

__attribute__((destructor)) void finalized_paged_allocator() { }

chunk_type_info** pipes::type_info;


#define PAGE_SIZE (32768)
size_t type_header_size(int type) {
    auto flag_bit_size = PAGE_SIZE / pow(2, type + 4); //Bit-Count for the block free flags
    auto header_size = sizeof(mapped_chunk); //The basic header itself

    return (size_t) (ceil(flag_bit_size / 8) + header_size);
}

#define H(type)                        \
if(left >= pow(2, type  + 4)) {        \
	result |= 1U << (unsigned) (type); \
	left -= pow(2, type  + 4);         \
}

uint8_t header_fill_mask(uint16_t left) {
    uint8_t result = 0;

    H(7);
    H(6);
    H(5);
    H(4);
    H(3);
    H(2);
    H(1);
    H(0);

    return result;
}

#undef H
#define H(type)                             \
if((mask & (1U << (unsigned) type)) > 0) {  \
	result += (int) pow(2, type  + 4);      \
}

uint16_t header_fill_mask_sum(uint8_t mask) {
    uint16_t result = 0;

    H(7);
    H(6);
    H(5);
    H(4);
    H(3);
    H(2);
    H(1);
    H(0);

    return result;
}

#undef H
#define H(type)                                         \
if((mask & (1 << type)) > 0) {                          \
	result += " " + to_string((int) pow(2, type  + 4)); \
}

std::string header_fill_mask_string(uint8_t mask) {
    std::string result;

    H(7);
    H(6);
    H(5);
    H(4);
    H(3);
    H(2);
    H(1);
    H(0);

    return result.empty() ? "none" : result.substr(1);
}

void generate_type_info(chunk_type_info& target, int type) {
    target.type = type;
    target.block_size = pow(2, type + 4);

    auto required_header_size = type_header_size(type);
    auto acquired_header_blocks = ceil((double) required_header_size / target.block_size);
    auto acquired_header_size = acquired_header_blocks * target.block_size;

    target.header_size = required_header_size;
    target.block_offset = acquired_header_size;
    target.block_count = PAGE_SIZE / pow(2, type + 4) - acquired_header_blocks;

    target.fill_mask = header_fill_mask(acquired_header_size - required_header_size);
    size_t fill_block_offset = target.block_offset;
    for(uint8_t index = 0; index < 8; index++) {
        if((target.fill_mask & (1U << index)) > 0) {
            auto fill_size = pow(2, index + 4);
            assert(fill_block_offset > fill_size);
            fill_block_offset -= fill_size;
            target.fill_offset[index] = fill_block_offset;
        } else {
            target.fill_offset[index] = 0;
        }
    }
    assert(fill_block_offset >= required_header_size);
}

__attribute__((constructor)) void initialized_paged_allocator() {
    pipes::type_info = new chunk_type_info*[9];

    for(int type = 0; type < 9; type++) {
        pipes::type_info[type] = new chunk_type_info();
        generate_type_info(*pipes::type_info[type], type);
    }
}

#define MAPPED_PAGE_SIZE (32768)
#define USE_LOCK
#ifdef USE_LOCK
#define SPIN_LOCK(name) while ((name).test_and_set(std::memory_order_acquire)) { ; }
#define SPIN_UNLOCK(name) (name).clear(std::memory_order_release);
#else
#define SPIN_LOCK(...)
	#define SPIN_UNLOCK(...)
#endif

PagedAllocator::PagedAllocator() {
    this->allocate_chunk_array(8 * 16);
}

PagedAllocator::~PagedAllocator() {

}

void* PagedAllocator::allocate_type(uint8_t type) {
    assert(type >= 0 && type <= 8);

    SPIN_LOCK(this->chunk_lock);
    uint8_t type_mask = 1U << type;
    mapped_chunk* chunk;
    size_t index;
    for(index = 0; index < this->chunk_count; index++) {
        chunk = chunk_array[index];
        test_chunk:
        if(!chunk || chunk->flag_deleted) continue;

        if(chunk->page_type == type && chunk->flag_free == 1) {
            auto& type_info = pipes::type_info[chunk->page_type];

            uint16_t blk_index = 0;
            uint8_t* flag_ptr = chunk->block_free_flags;
            while(!*flag_ptr) {
                flag_ptr++;
                blk_index++;
            }
            blk_index *= 8;

            uint8_t mask = 1;
            while((*flag_ptr & mask) == 0 && blk_index < type_info->block_count) {
                mask <<= 1U;
                blk_index++;
            }

            if(blk_index >= type_info->block_count) {
                chunk->flag_free = 0; //Chunk not free anymore
                if(index >= this->chunk_count)
                    break;
                else
                    continue;
            }

            chunk->block_free_flags[blk_index / 8] &= (uint8_t) ~mask; //Reset free flag
            SPIN_UNLOCK(this->chunk_lock);
            return (char*) chunk + type_info->block_offset + blk_index * type_info->block_size;
        } else if((pipes::type_info[chunk->page_type]->fill_mask & type_mask) > 0 && (chunk->padding_free_flags & type_mask) != 0) {
            chunk->padding_free_flags &= (uint8_t) ~(type_mask);
            SPIN_UNLOCK(this->chunk_lock);

            auto& type_info = pipes::type_info[chunk->page_type];
            return (char*) chunk + type_info->fill_offset[type];
        }
    }
    SPIN_UNLOCK(this->chunk_lock);

    if((chunk = this->allocate_chunk(type))) {
        SPIN_LOCK(this->chunk_lock);
        goto test_chunk;
    }
    return nullptr;
}

void PagedAllocator::free(void* ptr) {
    auto page_base = (mapped_chunk*) ((uintptr_t) ptr & ~(0xFFF)); //mmap aligns to 4096 bytes. We should be still somewhere over the base!
    bool page_valid = false;

    int page_offset = 0;
    auto page_size = 4096;
    SPIN_LOCK(this->chunk_lock);
    do {
        for(size_t chunk_index = 0; chunk_index + page_base->chunk_index < this->chunk_count; chunk_index += 265)
            if(this->chunk_array[page_base->chunk_index + chunk_index] == page_base) {
                goto page_found;
            }
        page_base = (mapped_chunk*) ((char*) page_base - page_size);
    } while(++page_offset < (PAGE_SIZE / 4096));
    assert(page_base && page_valid);

    page_found:
    assert(!page_base->flag_deleted); //Should never happen

    auto& type_info = pipes::type_info[page_base->page_type];
    if((uintptr_t) type_info->block_offset + (uintptr_t) page_base <= (uintptr_t) ptr) { //We've a chunk and not a padding!
        auto offset = (uintptr_t) ptr - (type_info->block_offset + (uintptr_t) page_base);
        assert(offset % type_info->block_size == 0);
        offset /= type_info->block_size;

        page_base->block_free_flags[offset / 8] |= (1 << (offset % 8));
        page_base->flag_free = 1;
        SPIN_UNLOCK(this->chunk_lock);
        return;
    } else {
        int index = 0;
        for(auto offset : type_info->fill_offset) {
            if(offset == 0) goto con;

            if(page_base + offset == ptr) {
                page_base->padding_free_flags |= 1 << index;
                goto free_finish;
            }

            con:
            index++;
        }

        free_finish:
        SPIN_UNLOCK(this->chunk_lock);
        return;
    }
}

mapped_chunk* PagedAllocator::allocate_chunk(uint8_t type) {
    auto chunk = (mapped_chunk*) mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert((uintptr_t) chunk % 4096 == 0);

    chunk->page_type = type;
    chunk->flag_deleted = false;
    chunk->flag_free = 1;
    chunk->padding_free_flags = pipes::type_info[type]->fill_mask;
    memset(chunk->block_free_flags, 0xFF, (int) ceil(pipes::type_info[type]->block_count / (double) 8) + 1);

    register_chunk:
    SPIN_LOCK(this->chunk_lock);
    uint16_t chunk_index = 0;
    uint8_t* flag_ptr = this->chunk_flags;
    while(!*flag_ptr) {
        flag_ptr++;
        chunk_index++;
    }
    chunk_index *= 8;

    uint8_t mask = 1;
    while((*flag_ptr & mask) == 0 && chunk_index < this->chunk_count) {
        mask <<= 1;
        chunk_index++;
    }

    if(chunk_index >= this->chunk_count) {
        auto chk_count = this->chunk_count;
        SPIN_UNLOCK(this->chunk_lock);

        SPIN_LOCK(this->chunk_allocate_lock);
        if(chk_count != this->chunk_count) { //Count has been changed
            SPIN_UNLOCK(this->chunk_allocate_lock);
            goto register_chunk;
        }
        this->allocate_chunk_array(this->chunk_count + 8);
        SPIN_UNLOCK(this->chunk_allocate_lock);
        goto register_chunk;
    }

    this->chunk_flags[chunk_index / 8] &= ~(mask);
    this->chunk_array[chunk_index] = chunk;
    chunk->chunk_index = (uint8_t) chunk_index;

    SPIN_UNLOCK(this->chunk_lock);

    return chunk;
}

void PagedAllocator::allocate_chunk_array(size_t new_length) {
    assert(new_length % 8 == 0);

    auto new_array = new_length > 0 ? new mapped_chunk*[new_length] : nullptr;
    auto new_flag_array_length = (size_t) ceil(new_length / 8.f) + 1;
    auto new_flag_array = new_length > 0 ? new uint8_t[new_flag_array_length] : nullptr;
    memset(new_flag_array, 0xFF, new_flag_array_length);
    memset(new_array, 0, new_length * sizeof(*new_array));

    SPIN_LOCK(this->chunk_lock);
    auto old_array = this->chunk_array;
    auto old_flag_array = this->chunk_flags;
    auto old_length = this->chunk_count;

    if(old_array && new_array)
        memcpy(new_array, old_array, old_length);
    if(new_flag_array && old_flag_array)
        memcpy(new_flag_array, old_flag_array, (size_t) ceil(old_length / 8.f));

    this->chunk_array = new_array;
    this->chunk_flags = new_flag_array;
    this->chunk_count = new_length;
    SPIN_UNLOCK(this->chunk_lock);

    delete[] old_array;
    delete[] old_flag_array;
}