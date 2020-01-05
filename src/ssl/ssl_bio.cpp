#include "pipes/ssl.h"
#include "pipes/misc/logger.h"

#include <cstring>
#include <assert.h>
#include <iostream>

#define BIO_C_SET_SSLHANDLE (1 | 0x8000)

int pipes::SSL::bio_puts(BIO *, const char *) {
	return 0;
}

int pipes::SSL::bio_gets(BIO *, char*, int) {
	return 0;
}

#ifdef USE_BORINGSSL
long pipes::SSL::bio_callback_ctrl(BIO *, int, bio_info_cb) {
    return 0L;
}
#else
long pipes::SSL::bio_callback_ctrl(BIO *_bio, int a, bio_info_cb *_callback) {
    return 0L;
}
#endif

int pipes::SSL::bio_write(BIO* self, const char* buffer, int length) {
	auto handle = static_cast<SSL*>(BIO_get_data(self));
	assert(handle);

	if(handle->_options->verbose_io)
	    LOG_VERBOSE(handle->logger(), "SSL::bio_write", "Got %p with length %i", buffer, length);
	handle->_callback_write(buffer_view{buffer, (size_t) length});
	return length;
}

int pipes::SSL::bio_read(BIO* self, char* buffer, int length) {
	auto handle = static_cast<SSL*>(BIO_get_data(self));
	assert(handle);

	return handle->buffer_read_read_bytes(buffer, length);
}

long pipes::SSL::bio_ctrl(BIO* self, int operation, long larg, void* parg) {
	//printf("ctrl(%p, %d, %li, %p);\n", self, operation, larg, parg);
    auto handle = static_cast<SSL*>(BIO_get_data(self));

	switch (operation) {
		case BIO_C_SET_SSLHANDLE:
		    BIO_set_data(self, parg);
		    BIO_set_init(self, parg != nullptr);
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
}

int pipes::SSL::bio_create(BIO* self) {
    BIO_set_data(self, nullptr);
	return 1;
}

int pipes::SSL::bio_destroy(BIO* self) {
    BIO_set_data(self, nullptr);
    BIO_set_init(self, 0);
	return 1;
}

BIO_METHOD* pipes::SSL::ssl_bio_method() {
    static BIO_METHOD* result{nullptr};
    if(result) return result;

    result = BIO_meth_new(BIO_TYPE_SOCKET, "SSLBio");
    if(result) {
        BIO_meth_set_write(result, &pipes::SSL::bio_write);
        BIO_meth_set_read(result, &pipes::SSL::bio_read);
        BIO_meth_set_puts(result, &pipes::SSL::bio_puts);
        BIO_meth_set_gets(result, &pipes::SSL::bio_gets);
        BIO_meth_set_ctrl(result, &pipes::SSL::bio_ctrl);
        BIO_meth_set_create(result, &pipes::SSL::bio_create);
        BIO_meth_set_destroy(result, &pipes::SSL::bio_destroy);
        BIO_meth_set_callback_ctrl(result, &pipes::SSL::bio_callback_ctrl);
    }
    return result;
}

bool pipes::SSL::initializeBio() {
	auto bio = BIO_new(pipes::SSL::ssl_bio_method());
	if(!bio) return false;
	if(auto err{BIO_ctrl(bio, BIO_C_SET_SSLHANDLE, 0, this)}; !err) {
		BIO_free(bio);
		return false;
	}
	SSL_set_bio(this->sslLayer, bio, bio);
	return true;
}