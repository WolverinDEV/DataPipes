#include <glib-2.0/glib.h>
#include <iostream>
#include "pipes/rtc/DTLSHandler.h"
#include "pipes/rtc/Protocol.h"

using namespace rtc;

DTLSHandler::DTLSHandler(std::shared_ptr<NiceWrapper> nice, rtc::NiceStreamId stream, std::shared_ptr<Config> config) : _config{std::move(config)}, _nice{std::move(nice)}, _nice_stream{stream} { }

DTLSHandler::~DTLSHandler() {
    this->reset();
}

void DTLSHandler::reset() {
    this->_initialized = false;
    this->_nice = nullptr;

    if(this->timer_mutex) {
        this->timer_mutex->lock();
        if(this->timer) {
            /* the timer still has a reference to the object */
            this->timer->handler = nullptr;
            this->timer_mutex->unlock();
        } else {
            /* time already deleted his object, only the mutex is left */
            this->timer_mutex->unlock();
            delete this->timer_mutex;
        }

        this->timer = nullptr;
        this->timer_mutex = nullptr;
    }

    auto econtext = std::exchange(this->event_context, nullptr);
    if(econtext) g_main_context_unref(econtext);

    auto tsource = std::exchange(this->connect_resend_interval, nullptr);
    if(tsource) {
        g_source_destroy(tsource);
        g_source_unref(tsource);
    }

    std::lock_guard buffer_lock(this->fail_buffer_lock);
    this->fail_buffer.clear();
}

bool DTLSHandler::initialize(std::string &error) {
    if(!this->_config) {
        error = "missing config";
        return false;
    }
    if(!this->_config->event_loop) {
        error = "Missing event loop";
        return false;
    }

    this->event_context = g_main_context_ref(this->_config->event_loop);
    if(!this->event_context) {
        error = "failed to ref context";
        return false;
    }

    this->_dtls = std::make_shared<pipes::TLS>();
    this->_dtls->direct_process(pipes::PROCESS_DIRECTION_IN, true);
    this->_dtls->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
    this->_dtls->logger(this->_config->logger);

    this->_dtls->callback_data([&](const pipes::buffer_view& data) {
        if(this->_config->verbose_io)
            LOG_VERBOSE(this->_config->logger, "DTLSPipe::dtls", "Decoded %i bytes", data.length());
        if(this->on_data)
            this->on_data(data);
    });
    this->_dtls->callback_write([&](const pipes::buffer_view& data) {
        /* keep in mind that peer connection streams are may read locked here */
        if(this->_config->verbose_io)
            LOG_VERBOSE(this->_config->logger, "DTLSPipe::dtls", "Encoded %i bytes", data.length());
        this->send_data(data, false);
    });
    this->_dtls->callback_error([&](int code, const std::string& error) {
        /* keep in mind that peer connection streams are may read locked here */
        LOG_ERROR(this->_config->logger, "DTLSPipe::dtls", "Received error %d on DTLS pipe: %s", code, error.c_str());
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

    this->timer_mutex = new std::mutex{};
    this->timer = new TimerData{};
    this->timer->handler = this;
    this->timer->mutex = this->timer_mutex;
    return true;
}

bool DTLSHandler::resend_buffers() {
    auto nice = this->_nice;
    if(!nice) return true; /* nice went away */

    std::lock_guard buffer_lock(this->fail_buffer_lock);
    while(!this->fail_buffer.empty()) {
        if(!nice->send_data(this->_nice_stream, 1, this->fail_buffer.front())) return false;
        this->fail_buffer.pop_front();
    }
    return true;
}

void DTLSHandler::send_data(const pipes::buffer_view &buffer, bool encrypt) {
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

void DTLSHandler::on_nice_ready() {
    this->resend_buffers();
    LOG_DEBUG(this->_config->logger, "DTLSPipe::on_nice_ready", "Nice stream has been initialized successfully. Initializing DTLS as %s", this->_role == DTLSHandler::Server ? "server" : "client");

    std::string error;
    if(!this->_dtls->initialize(error, this->_dtls_certificate, pipes::DTLS_v1_2, this->_role == DTLSHandler::Server ? pipes::SSL::SERVER : pipes::SSL::CLIENT, [](SSL_CTX* ctx) {
        SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32"); //Required for rt(c)p
        return true;
    })) {
        LOG_ERROR(this->_config->logger, "DTLSPipe::on_nice_ready", "Failed to initialize DTLS (%s)", error.c_str());
        return;
    }

    this->connect_resend_interval = g_timeout_source_new(500);
    g_source_set_callback(this->connect_resend_interval, [](gpointer timer_data_) {
        auto handler = reinterpret_cast<TimerData*>(timer_data_);
        std::lock_guard mlock{*handler->mutex};
        if(!handler->handler) return 0;
        if(handler->handler->_initialized) return 0;

        handler->handler->_dtls->continue_ssl();
        return 1;
    }, this->timer, [](gpointer timer_data_) {
        auto handler = reinterpret_cast<TimerData*>(timer_data_);
        auto mutex = handler->mutex;
        mutex->lock();
        if(handler->handler) {
            handler->handler->timer = nullptr;
            delete handler;
            mutex->unlock();
        } else {
            mutex->unlock();
            delete handler;
            delete mutex;
        }
    });
    g_source_attach(this->connect_resend_interval, this->event_context);

    /* begin initialize */
    this->_dtls->continue_ssl();
}

void DTLSHandler::process_incoming_data(const pipes::buffer_view &data) {
    if(this->_config->verbose_io)
        LOG_VERBOSE(this->_config->logger, "DTLSPipe::process_incoming_data", "incoming %i bytes", data.length());
    this->_dtls->process_incoming_data(data);
}