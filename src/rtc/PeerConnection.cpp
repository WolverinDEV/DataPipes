#include <sstream>
#include <iostream>
#include <cstring>
#include <utility>
#include <include/misc/endianness.h>
#include <cassert>
#include "sdptransform.hpp"
#include "include/rtc/ApplicationStream.h"
#include "include/rtc/AudioStream.h"
#include "include/rtc/PeerConnection.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace rtc;

PeerConnection::PeerConnection(const std::shared_ptr<Config>& config) : config(config) { }
PeerConnection::~PeerConnection() {}

void PeerConnection::reset() {
	if(this->nice) this->nice->finalize();
}

bool PeerConnection::initialize(std::string &error) {
	if(!this->config || !this->config->nice_config) {
		error = "Invalid config!";
		return false;
	}
	if(this->nice) {
		error = "invalid state! Please call reset() first!";
		return false;
	}

	shared_ptr<NiceStream> stream;
	{
		this->nice = make_unique<NiceWrapper>(this->config->nice_config);
		this->nice->logger(this->config->logger);

		this->nice->set_callback_local_candidate([&](const std::shared_ptr<NiceStream>& stream, const std::string& candidate){
			std::shared_ptr<Stream> handle;
			for(const auto& s : this->availible_streams()) {
				if(s->stream_id() == stream->stream_id) {
					handle = s;
					break;
				}
			}

			if(!handle) {
				LOG_ERROR(this->config->logger, "PeerConnection::callback_local_candidate", "Got local ice candidate for an invalid stream (id: %u)", stream->stream_id);
				return;
			}

			if(this->callback_ice_candidate) //application
				this->callback_ice_candidate(IceCandidate{candidate.length() > 2 ? candidate.substr(2) : candidate, handle->get_mid(), this->sdp_mline_index(handle)});
		});

		this->nice->set_callback_failed([&] {
			this->trigger_setup_fail(ConnectionComponent::NICE, "");
		});
		if(!this->nice->initialize(error)) {
			error = "Failed to initialize nice (" + error + ")";
			return false;
		}
	}

	return true;
}


bool PeerConnection::apply_offer(std::string& error, const std::string &raw_sdp) {
	auto sdp = sdptransform::parse(raw_sdp);

	LOG_VERBOSE(this->config->logger, "PeerConnection::apply_offer", "Got sdp offer:");
	LOG_VERBOSE(this->config->logger, "PeerConnection::apply_offer", "%s", sdp.dump(4).c_str());

	for(json& media_entry : sdp["media"]) {
		string type = media_entry["type"];
		if(type == "audio") {
			if(!this->stream_audio && !this->create_audio_stream(error)) {
				error = "failed to create audio handle: " + error;
				return false;
			}
		} else if(type == "application") {
			if(!this->stream_application && !this->create_application_stream(error)) {
				error = "failed to create audio handle: " + error;
				return false;
			}
		}
	}

	for(json& media_entry : sdp["media"]) {
		string type = media_entry["type"];
		if(type == "audio") {
			assert(this->stream_audio);
			if(!this->stream_audio->apply_sdp(sdp, media_entry)) {
				error = "failed to apply sdp for audio stream";
				return false;
			}
			this->sdp_media_lines.push_back(this->stream_audio);
		} else if(type == "application") {
			assert(this->stream_application);
			if(!this->stream_application->apply_sdp(sdp, media_entry)) {
				error = "failed to apply sdp for application stream";
				return false;
			}
			this->sdp_media_lines.push_back(this->stream_application);
		}
	}
	for(const auto& lines : this->sdp_media_lines)
		this->callback_new_stream(lines);

	if(!nice->apply_remote_sdp(error, raw_sdp)) return false;
	for(const auto& stream : nice->available_streams())
		nice->gather_candidates(stream);
	return true;
}

//FIXME test stream index and mid?
int PeerConnection::apply_ice_candidates(const std::deque<std::shared_ptr<rtc::IceCandidate>> &candidates) {
	int success_counter = 0;
	for(const auto& stream : this->availible_streams()) {
		for(const auto& candidate : candidates) {
			if(stream->get_mid() == candidate->sdpMid) {
				auto nice_handle = this->nice->find_stream(stream->stream_id());
				if(!nice_handle) {
					LOG_ERROR(this->config->logger, "PeerConnection::apply_ice_candidates", "Failed to find nice handle for %s (%u)", stream->get_mid().c_str(), stream->stream_id());
					continue;
				}
				if(!this->nice->apply_remote_ice_candidates(nice_handle, {"a=" + candidate->candidate})) { //TODO may even index?
					LOG_ERROR(this->config->logger, "PeerConnection::apply_ice_candidates", "Failed to apply candidate %s for %s (%u)", candidate->candidate.c_str(), stream->get_mid().c_str(), stream->stream_id());
				} else success_counter++;
			}
		}
	}
	return success_counter;
}

#define SESSION_ID_SIZE 16
std::string random_session_id() {
	const static char *numbers = "0123456789";
	srand((unsigned)time(nullptr));
	std::stringstream result;

	for (int i = 0; i < SESSION_ID_SIZE; ++i) {
		int r = rand() % 10;
		result << numbers[r];
	}
	return result.str();
}

std::string PeerConnection::generate_answer(bool candidates) {
	std::stringstream sdp;
	std::string session_id = random_session_id();

	/* General header */
	sdp << "v=0\r\n";
	//FIXME Copy username from request
	sdp << "o=mozilla...THIS_IS_SDPARTA-61.0.1 " << session_id << " 2 IN IP4 0.0.0.0\r\n";
	sdp << "s=AudioBridge 1234\r\n"; //Username?
	sdp << "t=0 0\r\n";

	auto nice_entries = this->nice->generate_local_sdp(candidates);

	for(const auto& entry : this->sdp_media_lines) {
		sdp << entry->generate_sdp();

		for(const auto& nice_entry : nice_entries) {
			if(nice_entry->index != this->sdp_mline_index(entry)) continue;
			//TODO if data is available

			sdp << "a=ice-ufrag:" << nice_entry->ice_ufrag << "\r\n";
			sdp << "a=ice-pwd:" << nice_entry->ice_pwd << "\r\n";
			for(const auto& candidate : nice_entry->candidates)
				sdp << "a=candidate:" << candidate << "\r\n";
			break;
		}
		if(candidates)
			sdp << "a=end-of-candidates\r\n";
	}
	this->sdp_media_lines.clear();

	return sdp.str();
}

void PeerConnection::on_nice_ready() {
	//This is within the main gloop!
	LOG_DEBUG(this->config->logger, "PeerConnection::nice", "successful connected");
	if(this->stream_audio)
		;//this->stream_audio->dtls->do_handshake();
}

void PeerConnection::trigger_setup_fail(rtc::PeerConnection::ConnectionComponent comp, const std::string &reason) {
	if(this->callback_setup_fail)
		this->callback_setup_fail(comp, reason);
}

bool PeerConnection::create_application_stream(std::string& error) {
	assert(!this->stream_application);

	auto stream = nice->add_stream("application"); //stream_application
	assert(stream); //FIXME!

	{
		auto config = make_shared<ApplicationStream::Configuration>();
		config->logger = this->config->logger;
		this->stream_application = make_shared<ApplicationStream>(this, stream->stream_id, config);
		stream->callback_ready = std::bind(&ApplicationStream::on_nice_ready, this->stream_application.get());
		if(!this->stream_application->initialize(error)) return false;
	}
	stream->callback_receive = [&](const std::string& data) { this->stream_application->process_incoming_data(data); };
	return true;
}

bool PeerConnection::create_audio_stream(std::string &error) {
	assert(!this->stream_audio);

	auto stream = nice->add_stream("audio");
	assert(stream); //FIXME!

	{
		auto config = make_shared<AudioStream::Configuration>();
		config->logger = this->config->logger;
		this->stream_audio = make_shared<AudioStream>(this, stream->stream_id, config);
		stream->callback_ready = std::bind(&AudioStream::on_nice_ready, this->stream_audio.get());
		if(!this->stream_audio->initialize(error)) return false;
	}

	stream->callback_receive = [&](const std::string& data) { this->stream_audio->process_incoming_data(data); };
	return true;
}

std::deque<std::shared_ptr<Stream>> PeerConnection::availible_streams() {
	std::deque<std::shared_ptr<Stream>> result;

	if(this->stream_audio)
		result.push_back(this->stream_audio);
	if(this->stream_application)
		result.push_back(this->stream_application);

	return result;
}