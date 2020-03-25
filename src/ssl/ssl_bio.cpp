#include "pipes/ssl.h"
#include "pipes/misc/logger.h"

#include <cstring>

int pipes::SSL::bio_puts(BIO *bio, const char *buffer) {
    return BIO_write(bio, buffer, strlen(buffer));
}

int pipes::SSL::bio_gets(BIO *, char*, int) { return -1; }

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

    if(handle->_options->verbose_io)
        LOG_VERBOSE(handle->logger(), "SSL::bio_read", "Want to read %u to %p", length, buffer);

    BIO_clear_retry_flags(self);
    auto read_result = handle->buffer_read_read_bytes(buffer, length);
    if(read_result > 0) return read_result;

    BIO_set_retry_read(self);
    return -1;
}

long pipes::SSL::bio_ctrl(BIO* self, int operation, long larg, void* parg) {
    //printf("ctrl(%p, %d, %li, %p);\n", self, operation, larg, parg);
    auto handle = static_cast<SSL*>(BIO_get_data(self));

	switch (operation) {
        case BIO_CTRL_RESET:
            return 0;
        case BIO_CTRL_EOF:
            return 0; /* socket isn't closed */
        case BIO_CTRL_WPENDING:
        case BIO_CTRL_PENDING:
            return 0;
        case BIO_CTRL_FLUSH:
            return 1;
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

BIO_METHOD* pipes::SSL::input_bio_method() {
    static BIO_METHOD* result{nullptr};
    if(result) return result;

    result = BIO_meth_new(BIO_TYPE_BIO, "SSLBio");
    if(result) {
        BIO_meth_set_write(result, &pipes::SSL::bio_write);
        BIO_meth_set_read(result, &pipes::SSL::bio_read);
        BIO_meth_set_puts(result, &pipes::SSL::bio_puts);
        //BIO_meth_set_gets(result, &pipes::SSL::bio_gets);
        BIO_meth_set_ctrl(result, &pipes::SSL::bio_ctrl);
        BIO_meth_set_create(result, &pipes::SSL::bio_create);
        BIO_meth_set_destroy(result, &pipes::SSL::bio_destroy);
        //BIO_meth_set_callback_ctrl(result, &pipes::SSL::bio_callback_ctrl);
    }
    return result;
}

bool pipes::SSL::initialize_bios() {
    auto bio = BIO_new(pipes::SSL::input_bio_method());
    if(!bio) return false;

    BIO_set_data(bio, this);
    BIO_set_init(bio, true);

    SSL_set_bio(this->ssl_handle_, bio, bio);
    return true;
}