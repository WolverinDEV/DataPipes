#pragma once

#include <stdint.h>
#include <iostream>
#include <bitset>

using namespace std;

#define _LE2BE(size, convert)                                                                                       \
template <typename T = int, typename BufferType, typename std::enable_if<                                           \
		std::is_same<typename std::remove_const<BufferType>::type, uint8_t>::value ||                               \
		std::is_same<typename std::remove_const<BufferType>::type, int8_t>::value ||                                \
		std::is_same<typename std::remove_const<BufferType>::type, char>::value ||                                  \
		std::is_same<typename std::remove_const<BufferType>::type, unsigned char>::value                            \
	, int>::type = 0>                                                                                               \
inline void le2be ##size(uint ##size ##_t num, BufferType* buffer,T offset = 0, T* offsetCounter = nullptr){        \
    convert;                                                                                                        \
    if(offsetCounter) *offsetCounter += (size) / 8;                                                                 \
}

#define _BE2LE(size, convert)                                                                                       \
template <typename T = int, typename BufferType, typename std::enable_if<                                           \
		std::is_same<typename std::remove_const<BufferType>::type, uint8_t>::value ||                               \
		std::is_same<typename std::remove_const<BufferType>::type, int8_t>::value ||                                \
		std::is_same<typename std::remove_const<BufferType>::type, char>::value ||                                  \
		std::is_same<typename std::remove_const<BufferType>::type, unsigned char>::value                            \
	, int>::type = 0, typename ResultType = uint ##size ##_t>                                                       \
inline ResultType be2le ##size(BufferType* buffer,T offset = 0, T* offsetCounter = nullptr){                        \
	ResultType result = 0;                                                                                          \
    convert;                                                                                                        \
    if(offsetCounter) *offsetCounter += (size) / 8;                                                                 \
	return result;                                                                                                  \
}

#define _LE2LE(size, convert)                                                                                       \
template <typename T = int, typename BufferType, typename std::enable_if<                                           \
		std::is_same<typename std::remove_const<BufferType>::type, uint8_t>::value ||                               \
		std::is_same<typename std::remove_const<BufferType>::type, int8_t>::value ||                                \
		std::is_same<typename std::remove_const<BufferType>::type, char>::value ||                                  \
		std::is_same<typename std::remove_const<BufferType>::type, unsigned char>::value                            \
	, int>::type = 0, typename ResultType = uint ##size ##_t>                                                       \
inline ResultType le2le ##size(BufferType* buffer,T offset = 0, T* offsetCounter = nullptr){                        \
	ResultType result = 0;                                                                                          \
    convert;                                                                                                        \
    if(offsetCounter) *offsetCounter += (size) / 8;                                                                 \
	return result;                                                                                                  \
}

//LE -> BE
_LE2BE(8, {
	buffer[offset + 0] = (BufferType) ((num) & 0xFF);
})

_LE2BE(16, {
    buffer[offset + 0] = (BufferType) ((num >> 8) & 0xFF);
    buffer[offset + 1] = (BufferType) ((num >> 0) & 0xFF);
})

_LE2BE(32, {
	buffer[offset + 0] = (BufferType) ((num >> 24) & 0xFF);
	buffer[offset + 1] = (BufferType) ((num >> 16) & 0xFF);
	buffer[offset + 2] = (BufferType) ((num >>  8) & 0xFF);
	buffer[offset + 3] = (BufferType) ((num >>  0) & 0xFF);
})

_LE2BE(64, {
	buffer[offset + 0] = (BufferType) ((num >> 56) & 0xFF);
	buffer[offset + 1] = (BufferType) ((num >> 48) & 0xFF);
	buffer[offset + 2] = (BufferType) ((num >> 40) & 0xFF);
	buffer[offset + 3] = (BufferType) ((num >> 32) & 0xFF);
	buffer[offset + 4] = (BufferType) ((num >> 24) & 0xFF);
	buffer[offset + 5] = (BufferType) ((num >> 16) & 0xFF);
	buffer[offset + 6] = (BufferType) ((num >>  8) & 0xFF);
	buffer[offset + 7] = (BufferType) ((num >>  0) & 0xFF);
})


//BE -> LE
_BE2LE(8, {
	result |= (ResultType) (uint8_t) buffer[offset + 0];
})

_BE2LE(16, {
	result |= (ResultType) (uint8_t) buffer[offset + 0] << 8;
	result |= (ResultType) (uint8_t) buffer[offset + 1] << 0;
})

_BE2LE(32, {
	result |= (ResultType) (uint8_t) buffer[offset + 0] << 24;
	result |= (ResultType) (uint8_t) buffer[offset + 1] << 16;
	result |= (ResultType) (uint8_t) buffer[offset + 2] <<  8;
	result |= (ResultType) (uint8_t) buffer[offset + 3] <<  0;
})

_BE2LE(64, {
	result += (ResultType) (uint8_t) buffer[offset + 0] << 56;
	result += (ResultType) (uint8_t) buffer[offset + 1] << 48;
	result += (ResultType) (uint8_t) buffer[offset + 2] << 40;
	result += (ResultType) (uint8_t) buffer[offset + 3] << 32;
	result += (ResultType) (uint8_t) buffer[offset + 4] << 24;
	result += (ResultType) (uint8_t) buffer[offset + 5] << 16;
	result += (ResultType) (uint8_t) buffer[offset + 6] <<  8;
	result += (ResultType) (uint8_t) buffer[offset + 7] <<  0;
})


//LE -> LE (These are more read helpers)
_LE2LE(8, {
	result |= (ResultType) (uint8_t) buffer[offset + 0];
})

_LE2LE(16, {
	result |= (ResultType) (uint8_t) buffer[offset + 0] << 0;
	result |= (ResultType) (uint8_t) buffer[offset + 1] << 8;
})

_LE2LE(32, {
	result |= (ResultType) (uint8_t) buffer[offset + 0] <<  0;
	result |= (ResultType) (uint8_t) buffer[offset + 1] <<  8;
	result |= (ResultType) (uint8_t) buffer[offset + 2] << 16;
	result |= (ResultType) (uint8_t) buffer[offset + 3] << 24;
})

_LE2LE(64, {
	result |= (ResultType) (uint8_t) buffer[offset + 0] <<  0;
	result |= (ResultType) (uint8_t) buffer[offset + 1] <<  8;
	result |= (ResultType) (uint8_t) buffer[offset + 2] << 16;
	result |= (ResultType) (uint8_t) buffer[offset + 3] << 24;
	result |= (ResultType) (uint8_t) buffer[offset + 4] << 32;
	result |= (ResultType) (uint8_t) buffer[offset + 5] << 40;
	result |= (ResultType) (uint8_t) buffer[offset + 6] << 48;
	result |= (ResultType) (uint8_t) buffer[offset + 7] << 56;
})