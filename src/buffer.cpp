//
// Created by wolverindev on 27.09.18.
//

#include "pipes/buffer.h"
#include <cstring>
#include <cassert>

using namespace pipes;
using namespace pipes::impl;

bool abstract_buffer_container::resize(size_t capacity, size_t data_length, size_t data_offset, size_t target_offset) {
	if(this->capacity >= capacity) return true;
	if(data_length + data_offset > this->capacity) return false;
	if(data_length + target_offset >= capacity) return false;

	void *target_address, *old_address = this->address;
	if(!this->_alloc(capacity, target_address)) return false;
	assert(target_address);
	assert(capacity > 0);

	if(data_length > 0)
		memcpy((char*) target_address + target_offset, (char*) this->address + data_offset, data_length);

	this->capacity = capacity;
	this->address = target_address;

	this->_free(old_address);
	return true;
}

buffer_view::buffer_view(const void *buffer, size_t length) {
	this->_data_type = data_type::pointer;
	this->_data.pointer.data = (void*) buffer;
	this->_data.pointer.capacity = length;
	this->_length = length;
}

buffer_view::buffer_view(const pipes::buffer_view &origin, size_t offset, ssize_t length) {
	if(origin.empty())
		return;

	if(offset + (length > 0 ? length : 0) > origin.length())
		return;

	if(length < 0)
		length = origin.length() - offset;

	this->_length = (size_t) length;
	if(origin._data_type == data_type::pointer) {
		this->_data_type = data_type::pointer;
		this->_data.pointer.data = (char*) origin.data_ptr() + offset;
		this->_data.pointer.capacity = (size_t) length;
	} else if(origin._data_type == data_type::buffer_container) {
		this->_data_type = data_type::buffer_container;
		this->_construct_buffer_container();

		this->_data.buffer_container = origin._data.buffer_container;
		this->view_offset = (origin.view_offset > 0 ? origin.view_offset : 0) + offset; /* update view offset */
	}

}

void* buffer_view::_data_ptr() const {
	void* _ptr;
	if(this->_data_type == data_type::pointer)
		_ptr = this->_data.pointer.data;
	else if(this->_data_type == data_type::buffer_container) {
		if(!this->_data.buffer_container)
			return nullptr;
		_ptr = this->_data.buffer_container->address;
	}
	else
		return nullptr;
	if(this->view_offset > 0)
		return (char*) _ptr + this->view_offset;
	return _ptr;
}

void* buffer_view::_data_ptr_origin() const {
	if(this->_data_type == data_type::pointer)
		return this->_data.pointer.data;
	else if(this->_data_type == data_type::buffer_container)
		return this->_data.buffer_container ? this->_data.buffer_container->address : nullptr;
	else
		return nullptr;
}

buffer_view buffer_view::_view(size_t offset, ssize_t length) const {
	if(this->length() < offset + (length > 0 ? length : 0)) return {};

	if(length < 0)
		length = this->length() - offset;

	return buffer_view{*this, offset, length};
}

buffer buffer_view::own_buffer() const {
	return buffer(*this);
}

buffer buffer_view::dup() const {
	auto result = buffer(this->length());
	memcpy(result.data_ptr(), this->data_ptr(), this->length());
	return result;
}

buffer buffer_view::dup(pipes::buffer target) const {
	target.resize(this->length());
	memcpy(target.data_ptr(), this->data_ptr(), this->length());
	return target;
}

void buffer_view::_destruct_buffer_container() {
	this->_data.buffer_container.~shared_ptr<impl::abstract_buffer_container>();
	/*
	this->data_type = data_type::pointer;
	this->data.pointer.data = nullptr;
	this->data.pointer.capacity = 0;
	 */
}

void buffer_view::_construct_buffer_container() {
	new (&this->_data.buffer_container) std::shared_ptr<impl::abstract_buffer_container>();
}

buffer::buffer(pipes::buffer &&ref) {
	*this = std::forward<buffer>(ref);
}

buffer::buffer(const pipes::buffer &ref) {
	*this = ref;
}

buffer::buffer(size_t length, uint8_t fill) : buffer(length) {
	memset(this->data_ptr(), fill, this->capacity());
}

buffer::buffer(const pipes::buffer_view &view) {
	this->_construct_buffer_container();
	this->_data_type = data_type::buffer_container;

	if(!view.empty()) {
		this->_length = view._length;
		if(view.owns_buffer() && view._data_type == data_type::buffer_container) {
			this->_data.buffer_container = view._data.buffer_container;
			this->view_offset = view.view_offset;
		} else {
			this->allocate_data(view.length());
			memcpy(this->data_ptr(), view.data_ptr(), this->_length);
		}
	}
}

buffer::buffer(pipes::buffer &parent, size_t view_offset, size_t view_length) : buffer() {
	assert(parent._data_type == data_type::buffer_container);
	assert(this->_data_type == data_type::buffer_container);
	this->_data.buffer_container = parent._data.buffer_container;

	if(parent.is_sub_view()) {
		this->view_offset = parent.view_offset+ view_offset;
		this->_length = view_length;
	} else {
		this->view_offset = view_offset;
		this->_length = view_length;
	}
}

size_t buffer::capacity() const {
	if(this->is_sub_view())
		return (size_t) this->_length;

	/* Buffer only works with buffer_container. Else something critical happened within the constructor */
	assert(this->_data_type == data_type::buffer_container);
	return this->_data.buffer_container ? this->_data.buffer_container->capacity : 0;
}

size_t buffer::capacity_origin() const {
	/* Buffer only works with buffer_container. Else something critical happened within the constructor */
	assert(this->_data_type == data_type::buffer_container);
	return this->_data.buffer_container ? this->_data.buffer_container->capacity : 0;
}

void buffer::resize_data(size_t length) {
	if(length > 0) {
		/* Buffer only works with buffer_container. Else something critical happened within the constructor */
		assert(this->_data_type == data_type::buffer_container);
		assert(this->_data.buffer_container); /* resize_data is an internal method. Callers should ensure that a container has been allocated! */
		if(!this->_data.buffer_container->address) {
			this->_data.buffer_container->alloc(length);
		} else if(this->_data.buffer_container->capacity < length) {
			this->_data.buffer_container->resize(length, this->_data.buffer_container->capacity, 0, 0);
		}
	}
}

bool buffer::resize(size_t size) {
	if(this->length() > size) {
		this->_length = size;
		return false;
	}

	if(this->is_sub_view()) {
		/* Buffer only works with buffer_container. Else something critical happened within the constructor */
		assert(this->_data_type == data_type::buffer_container);

		if(this->_data.buffer_container && this->_data.buffer_container->capacity > this->view_offset + size) {
			this->_length = size;
			return true;
		}

		this->allocate_data(this->view_offset + size);
		this->_length = size;
		return true;
	} else {
		if(this->capacity() < size)
			this->allocate_data(size);
		this->_length = size;
		return true;
	}
}

buffer buffer::range(size_t index, ssize_t length) {
	if(this->length() < index + (length > 0 ? length : 0)) return {};

	if(length < 0)
		length = this->length() - index;

	return buffer{*this, index, (size_t) length};
}

buffer& buffer::operator=(const pipes::buffer &other) {
	if(this->_data_type != data_type::buffer_container) {
		this->_construct_buffer_container();
		this->_data_type = data_type::buffer_container;
	}

	assert(other._data_type == data_type::buffer_container);
	this->_data.buffer_container = other._data.buffer_container;
	this->_length = other._length;
	this->view_offset = other.view_offset;

	return *this;
}

buffer& buffer::operator=(pipes::buffer &&other) {
	if(this->_data_type != data_type::buffer_container) {
		this->_construct_buffer_container();
		this->_data_type = data_type::buffer_container;
	}

	assert(other._data_type == data_type::buffer_container);
	this->_data.buffer_container = std::move(other._data.buffer_container);
	this->_length = other._length;
	this->view_offset = other.view_offset;

	other.view_offset = -1;
	other._length = 0;
	return *this;
}

bool buffer::append(const pipes::buffer_view &buffer) {
	auto current_length = this->length();
	if(this->capacity() < buffer.length() + current_length)
		this->resize(buffer.length() + this->length());

	memcpy((char*) this->data_ptr() + current_length, buffer.data_ptr(), buffer.length());
	return true;
}

bool buffer::append(const std::string &message) {
	auto current_length = this->length();
	if(this->capacity() < message.length() + current_length)
		this->resize(message.length() + this->length());

	memcpy((char*) this->data_ptr() + current_length, message.data(), message.length());
	return true;
}

ssize_t buffer::write(const pipes::buffer_view &buffer, ssize_t length, ssize_t offset_target, ssize_t offset_source) {
	if(length < 0) length = buffer.length();
	if(offset_source < 0) offset_source = 0;
	if(offset_target < 0) offset_target = 0;

	if((size_t) (length + offset_source) > buffer.length())
	    throw std::out_of_range("Source is out of buffer range!");

	return this->write((void *)buffer.data_ptr(), length, offset_target, offset_source);
}

ssize_t buffer::write(void *buffer, size_t length, ssize_t offset_target, ssize_t offset_source) {
	if(offset_source < 0) offset_source = 0;
	if(offset_target < 0) offset_target = 0;

	if(length + offset_target > this->length())
	    throw std::out_of_range("Destination is out of buffer range!");

	memcpy((char*) this->data_ptr() + offset_target, (char*) buffer + offset_source, length);
	return length;
}

ssize_t buffer::find(const std::string &str) {
	if(str.empty()) return 0;

	auto len = this->length();
	if(len < str.length()) return -1;
	len -= str.length();

	uint32_t str_idx;
	const char* c_str = str.data();
	const char* c_this = (char*) this->data_ptr();

	for(uint32_t index = 0; index <= len; index++) {
		if(c_str[0] == c_this[index]) {
			str_idx = 0;
			while(++str_idx < str.length())
				if(c_this[index + str_idx] != c_str[str_idx])
					break;
			if(str_idx == str.length()) return index;
		}
	}

	return -1;
}