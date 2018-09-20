#include <cstring>
#include <iostream>
#include "include/pipeline.h"

using namespace pipes;
using namespace std;

size_t impl::buffer_bytes_available(deque<string> &queue) {
    size_t result = 0;

    for(const auto& entry : queue)
        result += entry.length();

    return result;
}

size_t impl::buffer_peek_bytes(deque<string> &queue, char* result, size_t length) {
    size_t read = 0;
    auto it = queue.begin();
    while(read < length && it != queue.end()) {
        if(length - read >= it->length()) {
            memcpy(result + read, it->data(), it->length());
            read += it->length();
        } else {
            memcpy(result + read, it->data(), length - read);
            read += length - read;
        }
        it++;
    }
    return read;
}

size_t impl::buffer_read_bytes(deque<string> &queue, char* result, size_t length) {
    size_t read = 0;
    auto it = queue.begin();
    while(read < length && it != queue.end()) {
        if(it->length() == 0) it++;
        else if(length - read >= it->length()) {
            memcpy(result + read, it->data(), it->length());
            read += it->length();
            it++;
        } else {
            memcpy(result + read, it->data(), length - read);
            *it = it->substr(length - read);
            read += length - read;
        }
    }
    if(it == queue.begin())
        return read;

    queue.erase(queue.begin(), it);
    return read;
}