#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>
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
			buffer_view() = default;
			buffer_view(const buffer_view& /* buffer */, size_t /* offset */ = 0, ssize_t /* length */ = -1);

			buffer_view(const void* /* address */, size_t /* length */); /* base pointer initialisation */

			template <typename pointer_t, typename std::enable_if<!std::is_same<typename std::remove_all_extents<pointer_t>::type, void>::value, int>::type = 0>
			buffer_view(pointer_t* address, size_t length) : buffer_view((const void*) address, length){ }  /* Allow multible pointer types */

			size_t length() const;
			bool empty() const;

			template <typename pointer_t = void>
			inline const pointer_t* data_ptr() const { return (pointer_t*) this->_data_ptr(); }

			template <typename pointer_t = void>
			inline const pointer_t* data_ptr_origin() const { return (pointer_t*) this->_data_ptr_origin(); }

			template <typename T = char, typename N_T = T, typename std::enable_if<std::is_integral<T>::value && std::is_integral<N_T>::value, int>::type = 0>
			inline N_T at(size_t index) const {
				if(this->length() <= index) {
                    char buffer[256];
					print_formated(buffer, 256, "Index %lu is out of range. Max allowed %lu", index, this->length());
                    throw std::out_of_range(buffer);
                }
				return (N_T) *(T*) (this->data_ptr<char>() + index);
			}


			template <typename T = char, typename __unused = void, typename std::enable_if<std::is_integral<T>::value && std::is_same<__unused, void>::value, int>::type = 0>
			const T& at(size_t index) const {
				if(this->length() <= index) {
                    char buffer[256];
					print_formated(buffer, 256, "Index %lu is out of range. Max allowed %lu", index, this->length());
                    throw std::out_of_range(buffer);
                }
				return *(T*) (this->data_ptr<char>() + index);
			}

			template <typename T = char, typename N_T = T, typename std::enable_if<std::is_integral<T>::value && std::is_integral<N_T>::value && !std::is_same<T, N_T>::value, int>::type = 0>
			inline N_T operator[](size_t index) const { return this->at<T, N_T>(index); }

			template <typename T = char, typename __unused = void, typename std::enable_if<std::is_integral<T>::value && std::is_same<__unused, void>::value, int>::type = 0>
			const T& operator[](size_t index) const { return this->at<T, __unused>(index); }

			inline bool operator!() const { return !!this->data; }
			inline operator bool() const { return this->data != nullptr; }

			/* Converter functions */
			std::string string() const;
			const buffer_view view(size_t offset, ssize_t length = -1) const { return this->_view(offset, length); }
			buffer_view view(size_t offset, ssize_t length = -1) { return this->_view(offset, length); }

			bool owns_buffer() const;
			/* creates a new buffer any copy the data to it */
			buffer own_buffer() const;
			buffer dup() const;
			buffer dup(pipes::buffer /* target buffer */) const;
		protected:
			std::shared_ptr<impl::abstract_buffer_container> data;

			size_t _length = 0;
			ssize_t view_offset = -1;

			void* _data_ptr() const;
			void* _data_ptr_origin() const;
			buffer_view _view(size_t /* offset */, ssize_t /* length */ = -1) const;

	};

	class buffer : public buffer_view {
		public:
			buffer() = default;
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
					this->data->address = source;
					this->data->capacity = length;
					this->data->owns = true;
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
			T& at(size_t index) {
				if(this->length() <= index) {
				    char buffer[256];
					print_formated(buffer, 256, "Index %lu is out of range. Max allowed %lu", index, this->length());
                    throw std::out_of_range(buffer);
				}
				return *(T*) ((char*) this->data_ptr() + index);
			}

			template <typename T = char, typename N_T, typename std::enable_if<std::is_integral<T>::value && std::is_integral<N_T>::value, int>::type = 0>
			N_T at(size_t index) { return this->buffer_view::at<T, N_T>(index); };

			template <typename T = char, typename __unused = void, typename std::enable_if<std::is_integral<T>::value && std::is_same<__unused, void>::value, int>::type = 0>
			T& operator[](size_t index) { return this->at<T>(index); }

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
			void allocate_data(size_t length, allocator_t&& allocator = allocator_t(), deleter_t&& deleter = deleter_t()) {
				if(!this->data)
					this->data.reset(new impl::buffer_container<allocator_t, deleter_t>(std::forward<allocator_t>(allocator), std::forward<deleter_t>(deleter)));

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