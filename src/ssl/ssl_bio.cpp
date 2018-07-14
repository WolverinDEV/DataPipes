#include <cstring>
#include <assert.h>
#include <iostream>
#include "include/ssl.h"
#include "OpenSSLDefinitions.h"

#define BIO_C_SET_SSLHANDLE (1 | 0x8000)


int  (*pipes::SSL::bio_puts)             (BIO *, const char *) = [](BIO *, const char *) {
	return 0;
};
int  (*pipes::SSL::bio_gets)             (BIO *, char *, int) = [](BIO *, char*, int) {
	return 0;
};

#ifdef USE_BORINGSSL
	long (*pipes::SSL::bio_callback_ctrl)    (BIO *, int, bio_info_cb) = [](BIO *, int, bio_info_cb) {
		return 0L;
	};
#else
	long (*pipes::SSL::bio_callback_ctrl)    (BIO *, int, bio_info_cb *) = [](BIO *, int, bio_info_cb *) {
		return 0L;
	};
#endif

int(*pipes::SSL::bio_write)(BIO*, const char *, int) = [](BIO* self, const char* buffer, int length) -> int {
	auto handle = static_cast<SSL*>(self->ptr);
	assert(handle);

	handle->_callback_write(std::string(buffer, length));
	return length;
};

using namespace std;
int(*pipes::SSL::bio_read)(BIO *, char *, int) = [](BIO* self, char* buffer, int length) -> int {
	auto handle = static_cast<SSL*>(self->ptr);
	assert(handle);

	return handle->buffer_read_read_bytes(buffer, length);
};

long(*pipes::SSL::bio_ctrl)(BIO *, int, long, void*) = [](BIO* self, int operation, long larg, void* parg) -> long {
	//printf("ctrl(%p, %d, %li, %p);\n", self, operation, larg, parg);
    auto handle = static_cast<SSL*>(self->ptr);

	switch (operation) {
		case BIO_C_SET_SSLHANDLE:
			self->ptr = parg;
			self->init = self->ptr != nullptr;
			return 1L;
		case BIO_CTRL_PENDING:
			if(!handle) return -1L;
			return handle->buffer_read_bytes_available();
		case BIO_CTRL_FLUSH:
		case BIO_CTRL_PUSH:
		case BIO_CTRL_POP:
			return 1L;
		default:
			return 0L;
	}
};

int(*pipes::SSL::bio_create)(BIO *) = [](BIO* self) -> int {
	self->ptr = nullptr;
	return 1;
};

int(*pipes::SSL::bio_destroy)(BIO *) = [](BIO* self) -> int {
	self->ptr = nullptr;
	self->init = 0;
	return 1;
};

BIO_METHOD* pipes::SSL::SSLSocketBioMethods = new BIO_METHOD {
		BIO_TYPE_SOCKET,
		"SSLBio",
		pipes::SSL::bio_write,
		pipes::SSL::bio_read,
		pipes::SSL::bio_puts,
		pipes::SSL::bio_gets,
		pipes::SSL::bio_ctrl,
		pipes::SSL::bio_create,
		pipes::SSL::bio_destroy,
		pipes::SSL::bio_callback_ctrl
};

bool pipes::SSL::initializeBio() {
	auto bio = BIO_new(pipes::SSL::SSLSocketBioMethods);
	if(!BIO_ctrl(bio, BIO_C_SET_SSLHANDLE, 0, this)) {
		BIO_free(bio);
		return false;
	}
	SSL_set_bio(this->sslLayer, bio, bio);
	return true;
}