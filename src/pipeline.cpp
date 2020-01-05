#include "pipes/pipeline.h"

#include <cstring>
#include <iostream>

using namespace pipes;
using namespace std;

size_t impl::buffer_bytes_available(deque<buffer> &queue) {
    size_t result = 0;

    for(const auto& entry : queue)
        result += entry.length();

    return result;
}

size_t impl::buffer_peek_bytes(deque<buffer> &queue, char* result, size_t length) {
    size_t read = 0;
    auto it = queue.begin();
    while(read < length && it != queue.end()) {
        if(length - read >= it->length()) {
            memcpy(result + read, it->data_ptr(), it->length());
            read += it->length();
        } else {
            memcpy(result + read, it->data_ptr(), length - read);
            read += length - read;
        }
        it++;
    }
    return read;
}

size_t impl::buffer_read_bytes(deque<buffer> &queue, char* result, size_t length) {
    size_t read = 0;
    auto it = queue.begin();
    while(read < length && it != queue.end()) {
        if(it->length() == 0) it++;
        else if(length - read >= it->length()) {
            memcpy(result + read, it->data_ptr(), it->length());
            read += it->length();
            it++;
        } else {
            memcpy(result + read, it->data_ptr(), length - read);
            *it = it->range(length - read);
            read += length - read;
        }
    }
    if(it == queue.begin())
        return read;

    queue.erase(queue.begin(), it);
    return read;
}