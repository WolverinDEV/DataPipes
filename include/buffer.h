#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>
#include <cstring>
#include <cassert>
#include <exception>
#include "allocator.h"

#if defined(_MSC_VER)
    #include <BaseTsd.h>
	#include <stdexcept>

	typedef SSIZE_T ssize_t;
	#define print_formated sprintf_s
#else
	#define print_formated snprintf
#endif

namespace pipes {

	namespace impl {
		class abstract_buffer_container {
			public:
				virtual ~abstract_buffer_container() {
					assert(!this->address); //Implementation has to free!
				}

				virtual bool alloc(size_t capacity) {
					if(this->capacity >= capacity) return true;
					if(this->address) this->free();

					this->capacity = capacity;
					if(!this->_alloc(this->capacity, this->address)) {
						this->capacity = 0;
						this->address = nullptr;
						this->owns = false;
						return false;
					}
					this->owns = true;
					return true;
				}
				virtual bool resize(size_t /* capacity */, size_t /* data length */, size_t /* data offset */, size_t /* target offset */);
				virtual bool free() {
					if(this->address == nullptr) return true;
					if(!this->_free(this->address)) return false;

					this->owns = false;
					return true;
				}

				void* address = nullptr;
				size_t capacity = 0;
				bool owns = false;
			protected:
				virtual bool _free(void*& /* address */) = 0;
				virtual bool _alloc(size_t& /* capacity */, void*& /* address */) = 0;
		};

		template <typename allocator_t, typename deleter_t>
		class buffer_container : public abstract_buffer_container {
			public:
				buffer_container(allocator_t&& allocator, deleter_t&& deallocator) : allocator(std::forward<allocator_t>(allocator)), deallocator(std::forward<deleter_t>(deallocator)) {}
				virtual ~buffer_container() {
					this->_free(this->address);
					this->address = nullptr;
				}

				bool _alloc(size_t& length, void*& address) override {
					return this->allocator(length, address);
				}

				bool _free(void*& address) override {
					return this->deallocator(address);
				}

				allocator_t&& allocator;
				deleter_t&& deallocator;
		};
	}

	class buffer;
	class buffer_view {
			friend class buffer;
		public:
			struct data_type {
				enum value : uint8_t {
					buffer_container,
					pointer
				};
			};

			buffer_view() = default;
			/* copy constructor */
			inline buffer_view(const buffer_view& other) {
				*this = other;
			}

			/* copy operator */
			inline pipes::buffer_view& operator=(const pipes::buffer_view& other) {
				if(other._data_type == data_type::pointer) {
					if(this->_data_type != data_type::pointer)
						this->_destruct_buffer_container();
					memcpy((void*) &this->_data, (void*) &other._data, sizeof(this->_data)); /* the pointer data could be copied */
				} else if(other._data_type == data_type::buffer_container) {
					if(this->_data_type != data_type::buffer_container)
						this->_construct_buffer_container();
					this->_data.buffer_container = other._data.buffer_container;
				}

				this->_data_type = other._data_type;
				this->_length = other._length;
				this->view_offset = other.view_offset;
				return *this;
			}

			/* move constructor */
			inline buffer_view(buffer_view&& other) noexcept {
				if(other._data_type == data_type::pointer) {
					if(this->_data_type != data_type::pointer)
						this->_destruct_buffer_container();
					memcpy((void*) &this->_data, (void*) &other._data, sizeof(this->_data)); /* the pointer data could be copied */
				} else if(other._data_type == data_type::buffer_container) {
					if(this->_data_type != data_type::buffer_container)
						this->_construct_buffer_container();
					this->_data.buffer_container = std::move(other._data.buffer_container);
				}

				this->_data_type = other._data_type;
				this->_length = other._length;
				this->view_offset = other.view_offset;

				/* cleanup the other side */
				other._data_type = data_type::pointer;
				other._length = 0;
				other.view_offset = -1;
				memset((void*) &other._data, 0, sizeof(this->_data));
			}

			virtual ~buffer_view() {
				if(this->_data_type == data_type::buffer_container)
					this->_destruct_buffer_container();
			}

			buffer_view(const buffer_view& /* buffer */, size_t /* offset */, ssize_t /* length */ = -1);
			buffer_view(const void* /* address */, size_t /* length */); /* base pointer initialisation */

			template <typename pointer_t, typename std::enable_if<!std::is_same<typename std::remove_all_extents<pointer_t>::type, void>::value, int>::type = 0>
			buffer_view(pointer_t* address, size_t length) : buffer_view((const void*) address, length){ }  /* Allow multiple pointer types */

			inline size_t length() const { return this->_length; }
			inline bool empty() const { return this->_length == 0; }

			template <typename pointer_t = void>
			inline const pointer_t* data_ptr() const { return (pointer_t*) this->_data_ptr(); }

			template <typename pointer_t = void>
			inline const pointer_t* data_ptr_origin() const { return (pointer_t*) this->_data_ptr_origin(); }

			template <typename T = char, typename std::enable_if<std::is_integral<T>::value && std::is_const<T>::value, int>::type = 0>
			inline const T at(size_t index) const {
				if(this->length() <= index) {
                    char buffer[256];
					print_formated(buffer, 256, "Index %zu is out of range. Max allowed %zu", (size_t) index, (size_t) this->length());
                    throw std::out_of_range(buffer);
                }
				return *(T*) (this->data_ptr<char>() + index);
			}

			template <typename T = char, typename std::enable_if<std::is_integral<T>::value && !std::is_const<T>::value, int>::type = 0>
			inline const T& at(size_t index) const {
				if(this->length() <= index) {
					char buffer[256];
					print_formated(buffer, 256, "Index %zu is out of range. Max allowed %zu", (size_t) index, (size_t) this->length());
					throw std::out_of_range(buffer);
				}
				return *(T*) (this->data_ptr<char>() + index);
			}

			template <typename T = char, typename std::enable_if<std::is_integral<T>::value && std::is_const<T>::value, int>::type = 0>
			inline T operator[](size_t index) const { return this->at<T>(index); }

			template <typename T = char, typename std::enable_if<std::is_integral<T>::value && !std::is_const<T>::value, int>::type = 0>
			inline const T& operator[](size_t index) const { return this->at<T>(index); }

			inline bool operator!() const { return this->empty(); }
			inline operator bool() const { return !this->empty(); }

			/* Converter functions */
			[[nodiscard]] inline std::string string() const { return std::string(this->data_ptr<const char>(), this->length()); }
			[[nodiscard]] inline const buffer_view view(size_t offset, ssize_t length = -1) const { return this->_view(offset, length); }
			[[nodiscard]] inline buffer_view view(size_t offset, ssize_t length = -1) { return this->_view(offset, length); }

			[[nodiscard]] inline bool owns_buffer() const {
				if(this->_data_type != data_type::buffer_container)
					return false;
				auto buffer = this->_data.buffer_container;
				return buffer && buffer->owns;
			}
			/* creates a new buffer any copy the data to it */
			[[nodiscard]] buffer own_buffer() const;
			[[nodiscard]] buffer dup() const;
			[[nodiscard]] buffer dup(pipes::buffer /* target buffer */) const;
		protected:
			data_type::value _data_type = data_type::pointer;
			union __data {
				struct {
					void* data;
					size_t capacity = 0;
				} pointer;

				std::shared_ptr<impl::abstract_buffer_container> buffer_container;

				__data() {
					/* initialize the pointer to null */
					memset((void*) this, 0, sizeof(__data));
				}
				~__data() {};

				__data(const __data&) = delete;
				__data(__data&&) = delete;
			} _data{};

			size_t _length = 0;
			ssize_t view_offset = -1;

			void* _data_ptr() const;
			void* _data_ptr_origin() const;
			buffer_view _view(size_t /* offset */, ssize_t /* length */ = -1) const;

			void _destruct_buffer_container();
			void _construct_buffer_container();
	};

	class buffer : public buffer_view {
		public:
			buffer() {
				this->_data_type = data_type::buffer_container;
				this->_construct_buffer_container();
			}
			buffer(const buffer&);
			buffer(buffer&&);

			buffer(size_t /* length */, uint8_t /* fill */);

			template <typename allocator_t = default_allocator, typename deleter_t = default_deleter>
			buffer(void* source, size_t length, bool copy = true, allocator_t&& allocator = allocator_t(), deleter_t&& deleter = deleter_t()) {
				this->allocate_data<allocator_t, deleter_t>(0, std::forward<allocator_t>(allocator), std::forward<deleter_t>(deleter));

				this->_length = length;
				if(copy) {
					//TODO Error handling if resizing failed
					this->resize_data(length); /* ensure that the data has this length */
					this->write(source, length);
				} else {
					this->_data.buffer_container->address = source;
					this->_data.buffer_container->capacity = length;
					this->_data.buffer_container->owns = true;
				}
			}

			explicit buffer(const buffer_view& /* view */);

			template <typename allocator_t = default_allocator, typename deleter_t = default_deleter, typename std::enable_if<!std::is_integral<allocator_t>::value, int>::type = 0>
			explicit buffer(size_t length, allocator_t&& allocator = allocator_t(), deleter_t&& deleter = deleter_t()) {
				this->allocate_data<allocator_t, deleter_t>(0, std::forward<allocator_t>(allocator), std::forward<deleter_t>(deleter));
				if(length > 0)
					this->resize_data(length);
				this->_length = length;
			}


			size_t capacity() const;
			size_t capacity_origin() const;

			bool resize(size_t /* new size */);


			template <typename pointer_t = void>
			inline pointer_t* data_ptr() { return (pointer_t*) this->_data_ptr(); }

			template <typename pointer_t = void>
			inline pointer_t* data_ptr_origin() { return (pointer_t*) this->_data_ptr_origin(); }

			inline bool is_sub_view() const { return this->view_offset >= 0; }

			buffer range(size_t /* offset */, ssize_t /* length */ = -1);


			template <typename T = char, typename __unused = void, typename std::enable_if<std::is_integral<T>::value && std::is_same<__unused, void>::value, int>::type = 0>
			inline T& at(size_t index) {
				if(this->length() <= index) {
				    char buffer[256];
					print_formated(buffer, 256, "Index %zu is out of range. Max allowed %zu", (size_t) index, (size_t) this->length());
                    throw std::out_of_range(buffer);
				}
				return *(T*) ((char*) this->data_ptr() + index);
			}

			template <typename T = char, typename N_T, typename std::enable_if<std::is_integral<T>::value && std::is_integral<N_T>::value, int>::type = 0>
			inline N_T at(size_t index) { return this->buffer_view::at<T, N_T>(index); };

			template <typename T = char, typename __unused = void, typename std::enable_if<std::is_integral<T>::value && std::is_same<__unused, void>::value, int>::type = 0>
			inline T& operator[](size_t index) { return this->at<T>(index); }

			buffer& operator=(const buffer& /* other */);
			buffer& operator=(buffer&& /* other */);

			/* helper functions */
			ssize_t write(const buffer_view& /* source */, ssize_t /* length */ = -1, ssize_t /* target offset */ = -1, ssize_t /* source offset */ = -1);
			ssize_t write(void* /* source */, size_t /* length */, ssize_t /* target offset */ = -1, ssize_t /* source offset */ = -1);

			/* Append functions */
			bool append(const buffer_view& /* other */);
			inline buffer&operator+=(const buffer_view& other) { this->append(other);  return *this; }

			bool append(const std::string& /* message */);
			inline buffer&operator+=(const std::string& other) { this->append(other);  return *this; }

			ssize_t find(const std::string& /* str */);
		private:
			buffer(buffer& /* parent */, size_t /* view offset */, size_t /* view length */);

			void resize_data(size_t /* length */);

			template <typename allocator_t = default_allocator, typename deleter_t = default_deleter, typename std::enable_if<!std::is_integral<allocator_t>::value, int>::type = 0>
			inline void allocate_data(size_t length, allocator_t&& allocator = allocator_t(), deleter_t&& deleter = deleter_t()) {
				if(this->_data_type != data_type::buffer_container)
					this->_construct_buffer_container();
				this->_data_type = data_type::buffer_container;

				if(!this->_data.buffer_container)
					this->_data.buffer_container = std::make_shared<impl::buffer_container<allocator_t, deleter_t>>(std::forward<allocator_t>(allocator), std::forward<deleter_t>(deleter));

				if(length > 0)
					this->resize_data(length);
			}
	};

	template <typename T>
	inline std::basic_ostream<T>& operator<<(std::basic_ostream<T>& stream, const buffer_view& view) {
		if(view)
			stream.write((char*) view.data_ptr(), view.length());
		else
			stream << "nil";
		return stream;
	}
}
