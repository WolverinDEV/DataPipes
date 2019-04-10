#include "include/allocator.h"

using namespace std;
using namespace pipes;

bool system_allocator::operator()(size_t &length, void *&buffer) {
	buffer = malloc(length);
	return buffer != nullptr;
}

bool system_deleter::operator()(void *buffer) {
	if(!buffer) return false;

	free(buffer);
	return true;
}