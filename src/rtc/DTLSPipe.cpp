#include "pipes/rtc/DTLSPipe.h"
#include "pipes/rtc/Protocol.h"
#include "pipes/rtc/NiceWrapper.h"
#include "pipes/misc/logger.h"

using namespace rtc;

DTLSPipe::DTLSPipe(std::shared_ptr<NiceWrapper> nice, rtc::NiceStreamId stream, std::shared_ptr<Config> config) : _config{std::move(config)}, _nice{std::move(nice)}, _nice_stream{stream} {

}

DTLSPipe::~DTLSPipe() {
    this->reset();
}

void DTLSPipe::reset() {
    this->_initialized = false;
    this->_nice = nullptr;

    std::lock_guard buffer_lock(this->fail_buffer_lock);
    this->fail_buffer.clear();
}

bool DTLSPipe::initialize(std::string &error) {
    this->_dtls = std::make_shared<pipes::TLS>();
    this->_dtls->direct_process(pipes::PROCESS_DIRECTION_IN, true);
    this->_dtls->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
    this->_dtls->logger(this->_config->logger);

    this->_dtls->callback_data([&](const pipes::buffer_view& data) {
        LOG_VERBOSE(this->_config->logger, "MergedStream::dtls", "Decoded %i bytes", data.length());
        if(this->on_data)
            this->on_data(data);
    });
    this->_dtls->callback_write([&](const pipes::buffer_view& data) {
        /* keep in mind that peer connection streams are may read locked here */
        LOG_VERBOSE(this->_config->logger, "MergedStream::dtls", "Encoded %i bytes", data.length());
        this->send_data(data, false);
    });
    this->_dtls->callback_error([&](int code, const std::string& error) {
        /* keep in mind that peer connection streams are may read locked here */
        LOG_ERROR(this->_config->logger, "MergedStream::dtls", "Got error (%i): %s", code, error.c_str());
        //TODO: Better handling?
    });
    this->_dtls->callback_initialized = [&]{
        LOG_DEBUG(this->_config->logger, "DTLSPipe::dtls", "Initialized!");

        {
            /* Check the remote fingerprint */
            //TODO Test fingerprint with expected
            auto fingerprint = this->_dtls->remote_fingerprint();
            (void) fingerprint; //Remove the unused warning
        }

        this->_initialized = true;
        this->on_initialized();
    };
    this->_dtls_certificate = pipes::TLSCertificate::generate("DataPipes", 365);
    return true;
}

bool DTLSPipe::resend_buffers() {
    auto nice = this->_nice;
    if(!nice) return true; /* nice went away */

    std::lock_guard buffer_lock(this->fail_buffer_lock);
    while(!this->fail_buffer.empty()) {
        if(!nice->send_data(this->_nice_stream, 1, this->fail_buffer.front())) return false;
        this->fail_buffer.pop_front();
    }
    return true;
}

void DTLSPipe::send_data(const pipes::buffer_view &buffer, bool encrypt) {
    if(encrypt) {
        this->_dtls->send(buffer);
    } else {
        auto nice = this->_nice;
        if(!nice) return; /* nice went away */

        if(!nice->send_data(this->_nice_stream, 1, buffer)) {
            std::lock_guard lock{this->fail_buffer_lock};
            this->fail_buffer.push_back(buffer.own_buffer());
        }
    }
}

void DTLSPipe::on_nice_ready() {
    this->resend_buffers();
    LOG_DEBUG(this->_config->logger, "DTLSPipe::on_nice_ready", "Nice stream has been initialized successfully. Initializing DTLS as %s", this->_role == DTLSPipe::Server ? "server" : "client");

    std::string error;
    if(!this->_dtls->initialize(error, this->_dtls_certificate, pipes::DTLS_v1_2, this->_role == DTLSPipe::Server ? pipes::SSL::SERVER : pipes::SSL::CLIENT, [](SSL_CTX* ctx) {
        SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32"); //Required for rt(c)p
        return true;
    })) {
        LOG_ERROR(this->_config->logger, "DTLSPipe::on_nice_ready", "Failed to initialize DTLS (%s)", error.c_str());
        return;
    }

    /* begin initialize */
    this->_dtls->continue_ssl();
}

void DTLSPipe::process_incoming_data(const pipes::buffer_view &data) {
    LOG_VERBOSE(this->_config->logger, "MergedStream::process_incoming_data", "incoming %i bytes", data.length());
    this->_dtls->process_incoming_data(data);
}