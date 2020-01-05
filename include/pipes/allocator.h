#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>

namespace pipes {
	struct no_allocator {
		bool operator()(size_t& /* length */, void*& /* result ptr */) { return false; }
	};

	struct no_deleter {
		bool operator()(void* /* buffer */) { return false; }
	};

	struct system_allocator {
		bool operator()(size_t& /* length */, void*& /* result ptr */);
	};

	struct system_deleter {
		bool operator()(void* /* buffer */);
	};

	struct paged_allocator {
		bool operator()(size_t& /* length */, void*& /* result ptr */);
	};

	struct paged_deleter {
		bool operator()(void* /* buffer */);
	};

	typedef system_allocator default_allocator;
	typedef system_deleter default_deleter;

#ifndef WIN32
	//Each chunk has a size of 32768 bytes
	//The header has a prefix of 5 bytes
	//The header has n bits (n / 8) bytes of block flags
	struct mapped_chunk {
		uint8_t page_type;
		uint8_t chunk_index; //Index within the paged allocator array
		//std::atomic_flag page_lock; //One byte
		uint8_t padding_free_flags; //Indicates which type of padding is already used
		uint8_t flag_free: 1;
		uint8_t flag_deleted: 1;
		uint8_t __unused: 6;
	    uint8_t block_free_flags[1]; /* will contain one more bit than the chunk info specifies because it will be filled with 0xFF at any time representing "block_free_end" */
	};

	struct chunk_type_info {
		uint8_t type;

		uint16_t block_size;

		uint16_t header_size;

		uint16_t block_count;
		uint16_t block_offset;

		uint8_t fill_mask;
		uint16_t fill_offset[8];
	};
	extern chunk_type_info** type_info;

	class PagedAllocator {
		public:
			PagedAllocator();
			virtual ~PagedAllocator();

			void* allocate_type(uint8_t type);
			void free(void*);
		private:
			size_t chunk_count = 0;
			uint8_t* chunk_flags = nullptr;
			mapped_chunk** chunk_array = nullptr;
			std::atomic_flag chunk_lock = ATOMIC_FLAG_INIT;
			std::atomic_flag chunk_allocate_lock = ATOMIC_FLAG_INIT;

			mapped_chunk* allocate_chunk(uint8_t /* type */);
			void allocate_chunk_array(size_t /* length */);
	};
#endif
}