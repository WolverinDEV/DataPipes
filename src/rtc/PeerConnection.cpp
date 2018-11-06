#include <sstream>
#include <iostream>
#include <cstring>
#include <utility>
#include <cassert>
#include "sdptransform.hpp"
#include "include/rtc/NiceWrapper.h"
#include "include/rtc/PeerConnection.h"
#include "include/rtc/ApplicationStream.h"
#include "include/rtc/AudioStream.h"
#include "include/rtc/MergedStream.h"
#include "include/misc/endianness.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace rtc;

PeerConnection::PeerConnection(const std::shared_ptr<Config>& config) : config(config) { }
PeerConnection::~PeerConnection() {
	this->reset();
}

void PeerConnection::reset() {
	{
		unique_lock streams_lock(this->stream_lock);
		if(this->merged_stream) {
			auto stream = std::move(this->merged_stream);
			streams_lock.unlock();

			{
				unique_lock stream_lock(stream->_owner_lock);
				stream->_owner = nullptr;
				stream->_stream_id = 0;
			}
			{
				lock_guard buffer_lock(stream->fail_buffer_lock);
				stream->fail_buffer.clear();
			}

			streams_lock.lock();
		}
		if(this->stream_audio) {
			auto stream = std::move(this->stream_audio);
			streams_lock.unlock();

			{
				unique_lock stream_lock(stream->_owner_lock);
				stream->_owner = nullptr;
				stream->_stream_id = 0;
			}
			{
				lock_guard buffer_lock(stream->fail_buffer_lock);
				stream->fail_buffer.clear();
			}

			streams_lock.lock();
		}
		if(this->stream_audio) {
			auto stream = std::move(this->stream_application);
			streams_lock.unlock();

			{
				unique_lock stream_lock(stream->_owner_lock);
				stream->_owner = nullptr;
				stream->_stream_id = 0;
			}
			{
				lock_guard buffer_lock(stream->fail_buffer_lock);
				stream->fail_buffer.clear();
			}

			//streams_lock.lock(); //No need to lock here :)
		}
	}

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
			if(this->merged_stream) {
				for(const auto& s : this->available_streams()) {
					if(this->callback_ice_candidate) //application
						this->callback_ice_candidate(IceCandidate{candidate.length() > 2 ? candidate.substr(2) : candidate, s->get_mid(), this->sdp_mline_index(s)});
				}
			} else {
				std::shared_ptr<Stream> handle;

				for(const auto& s : this->available_streams()) {
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
			}
		});

		//FIXME!
		/*
		this->nice->set_callback_failed([&] {
			this->trigger_setup_fail(ConnectionComponent::NICE, "");
		});
		 */
		if(!this->nice->initialize(error)) {
			error = "Failed to initialize nice (" + error + ")";
			return false;
		}
	}

	return true;
}

typedef std::map<char, std::vector<sdptransform::grammar::Rule>> SDPRuleMap;
bool PeerConnection::apply_offer(std::string& error, const std::string &raw_sdp) {
	static bool sdptransform_setupped = false;
	if(!sdptransform_setupped) {
		LOG_VERBOSE(this->config->logger, "PeerConnection::apply_offer", "Setting up sdptransform");
		const SDPRuleMap* rules_map = &sdptransform::grammar::rulesMap;
		auto mutable_rules_map = (SDPRuleMap*) rules_map;
		auto& map = (*mutable_rules_map)['a'];

		map.insert(map.begin(),
				// a=sctp-port:5000
				   {
				           // name:
				           "sctp-port",
				           // push:
				           "",
				           // reg:
				           std::regex("^sctp-port:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[0-5]?[0-9]{1,4})$"),
				           // names:
				           { },
				           // types:
				           { 'd' },
				           // format:
				           "sctp-port:%d"
		           });
		sdptransform_setupped = true;
	}
	auto sdp = sdptransform::parse(raw_sdp);
	if(sdp.count("media") <= 0) {
		error = "Missing media entry";
		return false;
	}

	LOG_VERBOSE(this->config->logger, "PeerConnection::apply_offer", "Got sdp offer:");
	LOG_VERBOSE(this->config->logger, "PeerConnection::apply_offer", "%s", sdp.dump(4).c_str());

	//merged_nice_channels
	json& media = sdp["media"];
	if(!media.is_array()) return false;

	{
		if(media.size() <= 1) {
			this->merged_stream = nullptr;
		} else {
			string ice_ufrag, ice_pwd;
			for(json& media_entry : media) {
				if(media_entry.count("icePwd") <= 0) continue; //Fixme error handling
				if(media_entry.count("iceUfrag") <= 0) continue; //Fixme error handling

				if(ice_ufrag.empty() && ice_pwd.empty()) {
					ice_ufrag = media_entry["iceUfrag"];
					ice_pwd = media_entry["icePwd"];
				} else if(ice_ufrag == media_entry["iceUfrag"] && ice_pwd == media_entry["icePwd"]) { //TODO May test only for Ufrag?
					auto stream = this->nice->add_stream(media[0]["type"]);
					assert(stream);

					auto config = make_shared<MergedStream::Configuration>();
					config->logger = this->config->logger;

					unique_lock stream_lock(this->stream_lock);
					this->merged_stream = make_unique<MergedStream>(this, stream->stream_id, config);
					stream->callback_ready = [&] {
						if(this->merged_stream)
							this->merged_stream->on_nice_ready();
					};
					stream->callback_receive = [&](const pipes::buffer_view& data) {
						if(this->merged_stream)
							this->merged_stream->process_incoming_data(data);
					};

					if(!this->merged_stream->initialize(error)) {
						error = "Failed to initialized merged stream: " + error;
						return false;
					}
					break;
				}
			}
		}
	}

	for(json& media_entry : media) {
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
	for(json& media_entry : media) {
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


	if(this->merged_stream) {
		this->merged_stream->apply_sdp(sdp, nullptr);
		auto target_sdp = raw_sdp;
		auto m_index = target_sdp.find("m=");
		if(m_index == string::npos) {
			error = "missing m=";
			return false;
		}
		m_index = target_sdp.find("m=", m_index + 1);
		if(m_index != string::npos) target_sdp = target_sdp.substr(0, m_index);

		cout << target_sdp << endl;
		if(!nice->apply_remote_sdp(error, target_sdp)) return false;
	} else {
		if(!nice->apply_remote_sdp(error, raw_sdp)) return false;
	}

	for(const auto& stream : nice->available_streams())
		nice->gather_candidates(stream);

	return true;
}

int PeerConnection::apply_ice_candidates(const std::deque<std::shared_ptr<rtc::IceCandidate>> &candidates) {
	int success_counter = 0;
	for(const auto& candidate : candidates) {
		std::shared_ptr<NiceStream> nice_handle;
		if(this->merged_stream) {
			if(candidate->sdpMLineIndex != 0) continue;

			nice_handle = this->nice->find_stream(this->merged_stream->stream_id());
		} else {
			for(const auto& stream : this->available_streams()) {
				if(stream->get_mid() == candidate->sdpMid) {
					nice_handle = this->nice->find_stream(stream->stream_id());
					break;
				}
			}
		}
		if(!nice_handle) {
			LOG_ERROR(this->config->logger, "PeerConnection::apply_ice_candidates", "Failed to find nice handle for %s (%u)", candidate->sdpMid.c_str(), candidate->sdpMLineIndex);
			continue;
		}
		if(!this->nice->apply_remote_ice_candidates(nice_handle, {"a=" + candidate->candidate})) {
			LOG_ERROR(this->config->logger, "PeerConnection::apply_ice_candidates", "Failed to apply candidate %s for %s (%u)", candidate->candidate.c_str(), candidate->sdpMid.c_str(), candidate->sdpMLineIndex);
		} else success_counter++;
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
	sdp << "o=- " << session_id << " 2 IN IP4 0.0.0.0\r\n";
	sdp << "s=-\r\n"; //Username?
	sdp << "t=0 0\r\n";


	{
		sdp << "a=group:BUNDLE";
		for(const auto& entry : this->sdp_media_lines) {
			sdp << " " << entry->get_mid();
		}
		sdp << "\r\n";
	}
	sdp << "a=msid-semantic: WMS DataPipes\r\n";

	auto nice_entries = this->nice->generate_local_sdp(candidates);
	for(const auto& entry : this->sdp_media_lines) {
		sdp << entry->generate_sdp();

		for(const auto& nice_entry : nice_entries) {
			if(!this->merged_stream && nice_entry->index != this->sdp_mline_index(entry)) continue;
			if(!nice_entry->has.ice_ufrag) {
				LOG_ERROR(this->config->logger, "PeerConnection::generate_answer", "Media stream %s (%u) missing ice ufrag!", entry->get_mid().c_str(), entry->stream_id());
				continue;
			}
			if(!nice_entry->has.ice_pwd) {
				LOG_ERROR(this->config->logger, "PeerConnection::generate_answer", "Media stream %s (%u) missing ice pwd!", entry->get_mid().c_str(), entry->stream_id());
				continue;
			}
			if(!nice_entry->has.candidates && candidates) {
				LOG_ERROR(this->config->logger, "PeerConnection::generate_answer", "Media stream %s (%u) missing ice candidates, but its requested!", entry->get_mid().c_str(), entry->stream_id());
				continue;
			}

			if(this->merged_stream) {
				sdp << "a=fingerprint:sha-256 " << this->merged_stream->generate_local_fingerprint() << "\r\n";
			}
			sdp << "a=ice-ufrag:" << nice_entry->ice_ufrag << "\r\n";
			sdp << "a=ice-pwd:" << nice_entry->ice_pwd << "\r\n";
			//if(!candidates) //We send the candidates later
			sdp << "a=ice-options:trickle\r\n";

			for(const auto& candidate : nice_entry->candidates)
				sdp << "a=candidate:" << candidate << "\r\n";
			if(candidates)
				sdp << "a=end-of-candidates\r\n";
			break;
		}
	}

	return sdp.str();
}

bool PeerConnection::create_application_stream(std::string& error) {
	unique_lock stream_lock(this->stream_lock);
	assert(!this->stream_application);

	std::shared_ptr<NiceStream> stream;
	if(!this->merged_stream) {
		stream = nice->add_stream("application");
		if(!stream) {
			error = "failed to create stream!";
			return false;
		}

		stream->callback_receive = [&](const pipes::buffer_view& data) {
			if(this->stream_application)
				this->stream_application->process_incoming_data(data);
		};
		stream->callback_ready = [&]{
			if(this->stream_application)
				this->stream_application->on_nice_ready();
		};
	}

	{
		auto config = make_shared<ApplicationStream::Configuration>();
		config->logger = this->config->logger;
		this->stream_application = make_shared<ApplicationStream>(this, stream ? stream->stream_id : 0, config);
		if(!this->stream_application->initialize(error)) return false;
	}
	return true;
}

bool PeerConnection::create_audio_stream(std::string &error) {
	unique_lock stream_lock(this->stream_lock);
	assert(!this->stream_audio);

	std::shared_ptr<NiceStream> stream;
	if(!this->merged_stream) {
		stream = nice->add_stream("audio");
		if(!stream) {
			error = "failed to create stream!";
			return false;
		}

		stream->callback_receive = [&](const pipes::buffer_view& data) {
			if(this->stream_audio)
				this->stream_audio->process_incoming_data(data);
		};
		stream->callback_ready = [&]{
			if(this->stream_audio)
				this->stream_audio->on_nice_ready();
		};
	}

	{
		auto config = make_shared<AudioStream::Configuration>();
		config->logger = this->config->logger;
		this->stream_audio = make_shared<AudioStream>(this, stream ? stream->stream_id : 0, config);
		if(!this->stream_audio->initialize(error)) return false;
	}

	return true;
}

std::deque<std::shared_ptr<Stream>> PeerConnection::available_streams() {
	std::deque<std::shared_ptr<Stream>> result;

	{
		shared_lock stream_lock(this->stream_lock);
		if(this->stream_audio)
			result.push_back(this->stream_audio);
		if(this->stream_application)
			result.push_back(this->stream_application);
	}

	return result;
}