//
// Created by wolverindev on 27.09.18.
//

#include <cstring>
#include <cassert>
#include "include/buffer.h"

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
	this->data.reset(new buffer_container<no_allocator, no_deleter>(no_allocator(), no_deleter()));
	this->data->address = (void*) buffer;
	this->data->capacity = length;
	this->_length = length;
}

buffer_view::buffer_view(const pipes::buffer_view &origin, size_t offset, ssize_t length) {
	if(!origin.data) return;
	if(offset + (length > 0 ? length : 0) > origin.length()) return;

	if(length < 0)
		length = origin.length() - offset;

	this->data.reset(new buffer_container<no_allocator, no_deleter>(no_allocator(), no_deleter()));
	this->data->address = (char*) origin.data_ptr() + offset;
	this->data->capacity = (size_t) length;
	this->_length = (size_t) length;

}

void* buffer_view::_data_ptr() const {
	if(!this->data) return nullptr;
	if(this->view_offset >= 0)
		return (char*) this->data->address + this->view_offset;
	return this->data->address;
}

void* buffer_view::_data_ptr_origin() const {
	if(!this->data) return nullptr;
	return this->data->address;
}

size_t buffer_view::length() const {
	return this->_length;
}

bool buffer_view::empty() const {
	return !this->data || this->_length == 0;
}


std::string buffer_view::string() const {
	return std::string((const char*) this->data_ptr(), this->length());
}

buffer_view buffer_view::_view(size_t index, ssize_t length) const {
	if(this->length() < index + (length > 0 ? length : 0)) return {};

	if(length < 0)
		length = this->length() - index;

	return buffer_view{*this, index, length};
}

bool buffer_view::owns_buffer() const {
	if(!this->data) return true;
	return this->data->owns;
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
	if(view.data) {
		this->_length = view._length;
		if(view.data->owns) {
			this->data = view.data;
			this->view_offset = view.view_offset;
		} else {
			this->allocate_data(view.length());
			memcpy(this->data_ptr(), view.data_ptr(), this->_length);
		}
	}
}

buffer::buffer(pipes::buffer &parent, size_t view_offset, size_t view_length) {
	this->data = parent.data;

	if(parent.is_sub_view()) {
		this->view_offset = parent.view_offset + view_offset;
		this->_length = view_length;
	} else {
		this->view_offset = view_offset;
		this->_length = view_length;
	}
}

size_t buffer::capacity() const {
	if(this->is_sub_view())
		return (size_t) this->_length;

	if(this->data)
		return this->data->capacity;

	return 0;
}

size_t buffer::capacity_origin() const {
	if(this->data) return this->data->capacity;
	return 0;
}

void buffer::resize_data(size_t length) {
	if(length > 0) {
		if(!data->address) {
			this->data->alloc(length);
		} else if(this->data->capacity < length) {
			this->data->resize(length, this->data->capacity, 0, 0);
		}
	}
}

bool buffer::resize(size_t size) {
	if(this->length() > size) {
		this->_length = size;
		return false;
	}

	if(this->is_sub_view()) {
		if(this->data && this->data->capacity > this->view_offset + size) {
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
	this->data = other.data;
	this->_length = other._length;
	this->view_offset = other.view_offset;

	return *this;
}

buffer& buffer::operator=(pipes::buffer &&other) {
	this->data = std::move(other.data);
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

	if(length + offset_source > buffer.length()) std::__throw_out_of_range("Source is out of buffer range!");

	return this->write((void *)buffer.data_ptr(), length, offset_target, offset_source);
}

ssize_t buffer::write(void *buffer, size_t length, ssize_t offset_target, ssize_t offset_source) {
	if(offset_source < 0) offset_source = 0;
	if(offset_target < 0) offset_target = 0;

	if(length + offset_target > this->length()) std::__throw_out_of_range("Destination is out of buffer range!");

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