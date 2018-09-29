#include <include/errors.h>
#include <cstring>
#include <iostream>
#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"
#include "include/ssl.h"
#include "OpenSSLDefinitions.h"

using ProcessResult = pipes::ProcessResult;
using namespace std::chrono;
using namespace std;

pipes::SSL::SSL() : Pipeline("ssl") { }
pipes::SSL::~SSL() {
	this->finalize();
}

bool pipes::SSL::initialize(const std::shared_ptr<SSL_CTX>& ctx, Type type) {
    this->type = type;
    this->sslContext = ctx;
    this->sslLayer = SSL_new(ctx.get());
    if(!this->sslLayer) { return false; }
    if(type == SERVER)
        SSL_set_accept_state(this->sslLayer);
    else
        SSL_set_connect_state(this->sslLayer);
    if(!this->initializeBio()) return false;
    this->sslState = SSLSocketState::SSL_STATE_INIT;

    return true;
}

bool pipes::SSL::do_handshake() {
	if(this->type != CLIENT) return false;
	auto code = SSL_do_handshake(this->sslLayer);
	return code == 0;
}

void pipes::SSL::finalize() {
    if(this->sslLayer) SSL_free(this->sslLayer);
    this->sslLayer = nullptr;
    this->sslContext = nullptr;
    this->sslState = SSLSocketState::SSL_STATE_UNDEFINED;
}

bool pipes::SSL::isSSLHeader(const std::string &data) {
    if(data.length() < 0x05) return false; //Header too small!

    if(data[0] != 0x16) return false; //recordType=handshake

    if(data[1] < 1 || data[1] > 3) return false; //SSL version
    if(data[2] < 1 || data[2] > 3) return false; //TLS version

    return true;
}

ProcessResult pipes::SSL::process_data_in() {
    if(!this->sslLayer)
        return ProcessResult::PROCESS_RESULT_INVALID_STATE;

	unique_lock<mutex> lock(this->lock);
    if(this->sslState == SSLSocketState::SSL_STATE_INIT) {
        if(handshakeStart.time_since_epoch().count() == 0)
            handshakeStart = system_clock::now();
        /*
        auto buffered = this->bufferedBytes();
        if(buffered < 5) return; //Still not got the header!
        uint16_t frameLength;
        if(!this->peekBytes((char *) &frameLength, 2, 3)) return;

        if((frameLength + 5) > buffered) return; //Not enough buffered! (+5 for the SSL header)
        */

        auto code = SSL_accept(this->sslLayer);
        if(code <= 0) {
            if(SSL_get_error(this->sslLayer, code) != SSL_ERROR_SYSCALL) {
                _callback_error(PERROR_SSL_ACCEPT, "Could not proceed accept! (" + std::to_string(code) + "|" + std::to_string(SSL_get_error(this->sslLayer, code)) + ")");
                this->sslState = SSLSocketState::SSL_STATE_UNDEFINED;
                return ProcessResult::PROCESS_RESULT_ERROR;
            } else if(handshakeStart + milliseconds(7500) < system_clock::now()) {
                _callback_error(PERROR_SSL_TIMEOUT, "Handshake needs more than 7500ms");
                this->sslState = SSLSocketState::SSL_STATE_UNDEFINED;
                return ProcessResult::PROCESS_RESULT_ERROR;
            }
            return ProcessResult::PROCESS_RESULT_NEED_DATA;
        }
        this->sslState = SSLSocketState::SSL_STATE_CONNECTED;
        this->callback_initialized();

	    lock.unlock();
        this->process_data_in();
    } else if(this->sslState == SSLSocketState::SSL_STATE_CONNECTED) {
        int read = 0;
        while(this->sslState == SSLSocketState::SSL_STATE_CONNECTED) { //State could be updated while message processing!
	        buffer read_buffer(this->readBufferSize);
            read = SSL_read(this->sslLayer, read_buffer.data_ptr(), (int) read_buffer.capacity());
            if(read <= 0) break;
	        read_buffer.resize(read);

	        lock.unlock();
            this->_callback_data(read_buffer);
	        lock.lock();
        }
    }

    return PROCESS_RESULT_ERROR;
}

ProcessResult pipes::SSL::process_data_out() {
    if(!this->sslLayer) return ProcessResult::PROCESS_RESULT_INVALID_STATE;

    lock_guard<mutex> lock(this->lock);
    while(!this->write_buffer.empty()) {
    	auto front = this->write_buffer.front();
	    this->write_buffer.pop_front();
	    int index = 5;
	    while(index-- > 0) {
		    auto result = SSL_write(this->sslLayer, front.data_ptr(), front.length());
		    LOG_DEBUG(this->logger(), "SSL::process_data_out", "Write (%i): %i (bytes: %i) (empty: %i)", index, result, front.length(), this->write_buffer.size());
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
	X509 *rcert = SSL_get_peer_certificate(this->sslLayer);
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
		rcert = NULL;
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