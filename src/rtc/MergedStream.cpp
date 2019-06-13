#include "include/rtc/AudioStream.h"
#include "include/rtc/ApplicationStream.h"
#include "include/rtc/PeerConnection.h"
#include "include/rtc/MergedStream.h"
#include "include/tls.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"


using namespace std;
using namespace std::chrono;
using namespace rtc;

MergedStream::MergedStream(rtc::PeerConnection *peer, rtc::StreamId id, const std::shared_ptr<rtc::MergedStream::Configuration> &config) : Stream(peer, id), config(config) {}
MergedStream::~MergedStream() {}

bool MergedStream::initialize(std::string &error) {
	{
		this->dtls = make_unique<pipes::TLS>();
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_IN, true);
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
		this->dtls->logger(this->config->logger);

		this->dtls->callback_data([&](const pipes::buffer_view& data) {
			LOG_VERBOSE(this->config->logger, "MergedStream::dtls", "Decoded %i bytes", data.length());
			if(this->_owner->stream_application)
				this->_owner->stream_application->process_incoming_data(data);
		});
		this->dtls->callback_write([&](const pipes::buffer_view& data) {
			/* keep in mind that peer connection streams are may read locked here */
			LOG_VERBOSE(this->config->logger, "MergedStream::dtls", "Encoded %i bytes", data.length());
			this->send_data(data);
		});
		this->dtls->callback_error([&](int code, const std::string& error) {
			/* keep in mind that peer connection streams are may read locked here */
			LOG_ERROR(this->config->logger, "MergedStream::dtls", "Got error (%i): %s", code, error.c_str());
		});
		this->dtls->callback_initialized = [&](){
			this->on_dtls_initialized(this->dtls);
		};
	}

	this->dtls_certificate = pipes::TLSCertificate::generate("DataPipes", 365);
	return true;
}

bool MergedStream::reset(std::string &error) {
	if(this->dtls) this->dtls->finalize();
	this->dtls = nullptr;

	return true;
}

void MergedStream::send_data_dtls(const pipes::buffer_view &data) {
	this->dtls->send(data);
}

std::string MergedStream::generate_local_fingerprint() {
	if(this->dtls_certificate)
		return this->dtls_certificate->getFingerprint();
	return this->dtls->getCertificate()->getFingerprint();
}

bool MergedStream::apply_sdp(const nlohmann::json &sdp, const nlohmann::json &) {
	return true;
}

void MergedStream::on_nice_ready() {
	string error;

	LOG_DEBUG(this->config->logger, "MergedStream::on_nice_ready", "Nice stream has been initialized successfully. Initializing DTLS as %s", this->role == Role::Client ? "client" : "server");
	if(!this->dtls->initialize(error, this->dtls_certificate, pipes::DTLS_v1_2, this->role == Role::Client ? pipes::SSL::CLIENT : pipes::SSL::SERVER, [](SSL_CTX* ctx) {
		SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32"); //Required for rt(c)p
		return true;
	})) {
		LOG_ERROR(this->config->logger, "MergedStream::on_nice_ready", "Failed to initialize DTLS (%s)", error.c_str());
		return;
	}

	if(this->role == Role::Client) {
		this->dtls->do_handshake();
	}
}

string MergedStream::generate_sdp() {
	throw std::logic_error("merged stream could not generate a sdp!");
}

const string &MergedStream::get_mid() const {
	throw std::logic_error("merged stream could not have a mid!");
}

StreamType MergedStream::type() const {
	return CHANTYPE_MERGED;
}


void MergedStream::process_incoming_data(const pipes::buffer_view &data) {
	//FIXME in.length() >= sizeof(protocol::rtcp_header
	//FIXME in.length() >= sizeof(protocol::rtp_header)
	if (pipes::SSL::is_ssl((u_char*) data.data_ptr()) || (!protocol::is_rtp((void*) data.data_ptr()) && !protocol::is_rtcp((void*) data.data_ptr()))) {
		this->dtls->process_incoming_data(data);
		return;
	}
	if(!this->dtls_initialized) {
		LOG_VERBOSE(this->config->logger, "MergedStream::process_incoming_data", "incoming %i bytes", data.length());
		this->dtls->process_incoming_data(data);
	} else {
		if(protocol::is_rtp((void*) data.data_ptr())) {
			if(this->_owner->stream_audio)
				this->_owner->stream_audio->process_rtp_data(data);
			else; //TODO log error
		} else if(protocol::is_rtcp((void*) data.data_ptr())) {
			if(this->_owner->stream_audio)
				this->_owner->stream_audio->process_rtcp_data(data);
			else; //TODO log error
		}
		else {
			LOG_ERROR(this->config->logger, "MergedStream::process_incoming_data", "Got invalid packet (Unknown type)!");
			return;
		}
	}
}

void MergedStream::on_dtls_initialized(const std::unique_ptr<pipes::TLS> &handle) {
	LOG_DEBUG(this->config->logger, "MergedStream::dtls", "Initialized!");
	this->dtls_initialized = true;
	if(this->_owner->stream_audio)
		this->_owner->stream_audio->on_dtls_initialized(handle);
	if(this->_owner->stream_application)
		this->_owner->stream_application->on_dtls_initialized(handle);
}
