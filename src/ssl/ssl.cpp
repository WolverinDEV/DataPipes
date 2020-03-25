#include "pipes/ssl.h"
#include "pipes/misc/logger.h"
#include "pipes/errors.h"

#include <cstring>
#include <iostream>
#include <openssl/err.h>


using ProcessResult = pipes::ProcessResult;
using namespace std::chrono;
using namespace std;

#ifdef USE_BORINGSSL
int pipes::SSL::compiled_boringssl = 1;
#else
int pipes::SSL::compiled_boringssl = 0;
#endif

pipes::SSL::SSL() : Pipeline("ssl") {
    assert(this->included_boringssl == this->compiled_boringssl);
}
pipes::SSL::~SSL() {
    this->finalize();
}

const pipes::SSL::Options::KeyPair pipes::SSL::Options::EmptyKeyPair{nullptr, nullptr};

int pipes::SSL::_sni_callback(::SSL* handle, int* ad, void* _ptr_ssl) {
    auto ssl = reinterpret_cast<pipes::SSL*>(_ptr_ssl);
    assert(ssl->ssl_handle() == handle);

    auto servername = SSL_get_servername(handle, TLSEXT_NAMETYPE_host_name);
    if(servername != nullptr) {
        LOG_DEBUG(ssl->logger(), "SSL::sni_callback", "Received SNI extension with value \"%s\"", servername);
        if(ssl->_options->servername_keys.count(servername) > 0) {
            auto key = ssl->_options->servername_keys.at(servername);
            if(key.first && key.second) {
                LOG_DEBUG(ssl->logger(), "SSL::sni_callback", "Using special defined certificate.");

                if(!SSL_use_PrivateKey(handle, &*key.first))
                    return SSL_TLSEXT_ERR_ALERT_FATAL;

                if(!SSL_use_certificate(handle, &*key.second))
                    return SSL_TLSEXT_ERR_ALERT_FATAL;

                if(ssl->_options->free_unused_keypairs)
                    ssl->_options->servername_keys.clear();
                return SSL_TLSEXT_ERR_OK;
            }
        }
    } else {
        LOG_DEBUG(ssl->logger(), "SSL::sni_callback", "Received SNI extension with empty value.");
    }

    {
        auto key = ssl->_options->default_keypair();
        if(key.first && key.second) {
            LOG_DEBUG(ssl->logger(), "SSL::sni_callback", "Using default certificate");

            if(!SSL_use_PrivateKey(handle,&*key.first))
                return SSL_TLSEXT_ERR_ALERT_FATAL;

            if(!SSL_use_certificate(handle, &*key.second))
                return SSL_TLSEXT_ERR_ALERT_FATAL;
        } else {
            LOG_DEBUG(ssl->logger(), "SSL::sni_callback", "Haven't yet setupped any certificate. Trying without.");
        }

        if(ssl->_options->free_unused_keypairs)
            ssl->_options->servername_keys.clear();
    }
    return SSL_TLSEXT_ERR_OK;
}

bool pipes::SSL::initialize(const std::shared_ptr<pipes::SSL::Options> &options, std::string& error) {
    if(!options->context_method) {
        error = "missing context method";
        return false;
    }

    this->_options = options;


    this->sslContext = shared_ptr<SSL_CTX>(SSL_CTX_new(options->context_method), SSL_CTX_free);
    if(!this->sslContext) {
        error = "failed to allocate ssl context";
        return false;
    }

    if(options->context_initializer)
        options->context_initializer(&*this->sslContext); /* TODO: Test result */

    this->ssh_handle_ = SSL_new(&*this->sslContext);
    if(!this->ssh_handle_) {
        error = "failed to allocate ssl context";
        return false;
    }

    if(options->type == SERVER) {
        SSL_set_accept_state(this->ssh_handle_);
    } else {
        SSL_set_connect_state(this->ssh_handle_);
    }
    if(options->ssl_initializer)
        options->ssl_initializer(this->ssh_handle_); /* TODO: Test result */

    if(options->servername_keys.size() > 1 || options->enforce_sni) {
        SSL_CTX_set_tlsext_servername_callback(&*this->sslContext, pipes::SSL::_sni_callback);
        SSL_CTX_set_tlsext_servername_arg(&*this->sslContext, this);
    } else if(options->servername_keys.size() == 1) {
        auto default_keypair = options->servername_keys.begin();
        if(!SSL_use_PrivateKey(this->ssh_handle_, &*default_keypair->second.first)) {
            error = "failed to use private key";
            return false;
        }

        if(!SSL_use_certificate(this->ssh_handle_, &*default_keypair->second.second)) {
            error = "failed to use certificate";
            return false;
        }

        if(options->type == CLIENT && !default_keypair->first.empty()) {
            if(!SSL_set_tlsext_host_name(this->ssh_handle_, default_keypair->first.c_str())){
                error = "failed to set tlsext hostname";
                return false;
            }
        }

        if(options->free_unused_keypairs)
            options->servername_keys.clear();
    } else {
        if(!SSL_CTX_get0_privatekey(&*this->sslContext)) {
            error = "no private key given";
            return false;
        }

        if(!SSL_CTX_get0_certificate(&*this->sslContext)) {
            error = "no certificate given";
            return false;
        }
    }

    if(!this->initializeBio()) {
        error = "failed to initialize bio";
        return false;
    }
    this->ssl_state_ = SSLSocketState::SSL_STATE_CONNECTING;

    return true;
}

void pipes::SSL::continue_ssl() {
    lock_guard slock{this->ssl_mutex_};
    return this->continue_ssl_nolock();
}

void pipes::SSL::continue_ssl_nolock() {
    if(this->ssl_state_ != SSLSocketState::SSL_STATE_CONNECTING) return;

    if(handshake_start_timestamp.time_since_epoch().count() == 0)
        handshake_start_timestamp = std::chrono::system_clock::now();

    auto code = this->_options->type == Type::CLIENT ? SSL_connect(this->ssh_handle_) : SSL_accept(this->ssh_handle_);
    switch (SSL_get_error(this->ssh_handle_, code)) {
        case SSL_ERROR_NONE:
            /* validate certificate! */
            this->ssl_state_ = SSLSocketState::SSL_STATE_CONNECTED;
            this->callback_initialized();
            this->process_data_in();
            return;

        case SSL_ERROR_WANT_READ:
            if(handshake_start_timestamp + milliseconds(7500) < system_clock::now()) {
                _callback_error(PERROR_SSL_TIMEOUT, "Handshake needs more than 7500ms");
                this->ssl_state_ = SSLSocketState::SSL_STATE_UNDEFINED;
            }

            break;

        case SSL_ERROR_WANT_WRITE:
            break;

        case SSL_ERROR_SYSCALL:
            _callback_error(PERROR_SSL_TIMEOUT, "syscall error (" + std::to_string(errno) + "/" + strerror(errno) + ")");
            this->ssl_state_ = SSLSocketState::SSL_STATE_UNDEFINED;
            return;

        case SSL_ERROR_ZERO_RETURN:
        default:
            _callback_error(PERROR_SSL_TIMEOUT, "unknown error " + std::to_string(SSL_get_error(this->ssh_handle_, code)));
            this->ssl_state_ = SSLSocketState::SSL_STATE_UNDEFINED;
            return;
    }
}

void pipes::SSL::finalize() {
    if(this->ssh_handle_) SSL_free(this->ssh_handle_);
    this->ssh_handle_ = nullptr;
    this->sslContext = nullptr;
    this->ssl_state_ = SSLSocketState::SSL_STATE_UNDEFINED;
}

bool pipes::SSL::isSSLHeader(const std::string &data) {
    if(data.length() < 0x05) return false; //Header too small!

    if(data[0] != 0x16) return false; //recordType=handshake

    if(data[1] < 1 || data[1] > 3) return false; //SSL version
    if(data[2] < 1 || data[2] > 3) return false; //TLS version

    return true;
}

ProcessResult pipes::SSL::process_data_in() {
    if(!this->ssh_handle_) {
        return ProcessResult::PROCESS_RESULT_INVALID_STATE;
    }

    lock_guard slock{this->ssl_mutex_};
    if(this->ssl_state_ == SSLSocketState::SSL_STATE_CONNECTING) {
        this->continue_ssl_nolock();
        return ProcessResult::PROCESS_RESULT_OK;
    } else if(this->ssl_state_ == SSLSocketState::SSL_STATE_CONNECTED) {
        int read = 0;
        while(this->ssl_state_ == SSLSocketState::SSL_STATE_CONNECTED) { //State could be updated while message processing!
            buffer read_buffer(this->readBufferSize);
            read = SSL_read(this->ssh_handle_, read_buffer.data_ptr(), (int) read_buffer.capacity());
            if(read <= 0) break;
            read_buffer.resize(read);

            /* callback may changes ssl state */
            this->_callback_data(read_buffer);
        }

        return PROCESS_RESULT_OK;
    }

    return PROCESS_RESULT_ERROR;
}

ProcessResult pipes::SSL::process_data_out() {
    if(!this->ssh_handle_) return ProcessResult::PROCESS_RESULT_INVALID_STATE;

    lock_guard slock{this->ssl_mutex_};
    while(!this->write_buffer.empty()) {
        auto front = this->write_buffer.front();
        this->write_buffer.pop_front();
        int index = 5;
        while(index-- > 0) {
            auto result{SSL_write(this->ssh_handle_, front.data_ptr(), front.length())};
            if(this->_options->verbose_io) {
                LOG_VERBOSE(this->logger(), "SSL::process_data_out", "Write (%i): %i (bytes: %i) (empty: %i)", index, result, front.length(), this->write_buffer.size());
            }
            if(result > 0) break;
        }
    }
    return PROCESS_RESULT_OK;
}

/*

struct uint24_t {
    uint32_t value : 24;
};

bool SSLSocket::isSSLHandschake(const std::string& data, bool full = false) {
    if(data.length() < (full ? 0xF : 0x05)) return false; //Header too small!

    if(data[0] != 0x16) return false; //recordType=handshake

    if(data[1] < 1 || data[1] > 3) return false; //SSL version
    if(data[2] < 1 || data[2] > 3) return false; //TLS version

    //The packet content (optional)
    if(data.length() > 5 || full) {
        if(data[5] != 0x01) return false; //Must be manager hello
    }

    if(full) { //We could check the lengths
        uint16_t recordLength = *(uint16_t*) &data[1];
        if(data.length() - recordLength != 0x05) return false; //Invalid length tag!


        uint24_t handschakeLength = *(uint24_t*) &data[6];
        if(data.length() - handschakeLength.value != 0x08) return false; //Test if handshake is correct!
    }

    return true;
}
 */

std::string pipes::SSL::remote_fingerprint() {
    lock_guard slock{this->ssl_mutex_};
    X509 *rcert = SSL_get_peer_certificate(this->ssh_handle_);
    if(!rcert) {
        LOG_ERROR(this->_logger, "SSL::remote_fingerprint", "Failed to generate remote fingerprint (certificate missing)");
        return "";
    } else {
        unsigned int rsize;
        unsigned char rfingerprint[EVP_MAX_MD_SIZE];
        char remote_fingerprint[160];
        char *rfp = (char *) &remote_fingerprint;
        if (false) {
            X509_digest(rcert, EVP_sha1(), (unsigned char *) rfingerprint, &rsize);
        } else {
            X509_digest(rcert, EVP_sha256(), (unsigned char *) rfingerprint, &rsize);
        }
        X509_free(rcert);
        rcert = nullptr;
        unsigned int i = 0;
        for (i = 0; i < rsize; i++) {
            snprintf(rfp, 4, "%.2X:", rfingerprint[i]);
            rfp += 3;
        }
        *(rfp - 1) = 0;

        LOG_VERBOSE(this->_logger, "SSL::remote_fingerprint", "Generated remote fingerprint: %s", remote_fingerprint);
        return string(remote_fingerprint);
    }
}