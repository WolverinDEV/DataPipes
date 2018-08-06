//
// Created by wolverindev on 03.08.18.
//

#include <sstream>
#include <iostream>
#include <cstring>
#include <utility>
#include <include/misc/endianness.h>
#include <cassert>
#include "include/rtc/PeerConnection.h"
#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace rtc;

// SCTP PPID Types
#define PPID_CONTROL 50
#define PPID_STRING 51
#define PPID_BINARY 53
#define PPID_STRING_EMPTY 56
#define PPID_BINARY_EMPTY 57

// DataChannel Control Types
#define DC_TYPE_OPEN 0x03
#define DC_TYPE_ACK 0x02

uint16_t DataChannel::id() const { return this->_id; }
std::string DataChannel::protocol() const { return this->_protocol; }
std::string DataChannel::lable() const { return this->_lable; }
DataChannel::DataChannel(PeerConnection* owner, uint16_t id, std::string lable, std::string protocol) : owner(owner), _id(id), _lable(std::move(lable)), _protocol(std::move(protocol)) {}

void DataChannel::send(const std::string &message, rtc::DataChannel::MessageType type) {
	this->owner->sendSctpMessage({message, this->id(), type == DataChannel::BINARY ? PPID_BINARY : PPID_STRING});
}

void DataChannel::close() {
	this->owner->close_datachannel(this);
}

PeerConnection::PeerConnection(const std::shared_ptr<Config>& config) : config(config) { }
PeerConnection::~PeerConnection() {}

void PeerConnection::reset() {
	if(this->sctp) this->sctp->finalize();
	if(this->dtls) this->dtls->finalize();
	if(this->nice) this->nice->finalize();
	this->mid = "";
	this->active_channels.clear();
}

bool PeerConnection::initialize(std::string &error) {
	if(!this->config || !this->config->nice_config) {
		error = "Invalid config!";
		return false;
	}
	if(this->nice || this->dtls || this->sctp) {
		error = "invalid state! Please call reset() first!";
		return false;
	}
	{
		this->nice = make_unique<NiceWrapper>(this->config->nice_config);
		this->nice->logger(this->config->logger);

		this->nice->set_callback_local_candidate([&](const std::string& candidate){
			if(this->callback_ice_candidate)
				this->callback_ice_candidate(IceCandidate{candidate.length() > 2 ? candidate.substr(2) : candidate, this->mid, 0});
		});
		this->nice->set_callback_ready(bind(&PeerConnection::on_nice_ready, this));
		this->nice->set_callback_recive([&](const std::string& data) { this->dtls->process_incoming_data(data); });
		this->nice->set_callback_failed([&] {
			this->trigger_setup_fail(ConnectionComponent::NICE, "");
		});
		if(!this->nice->initialize(error)) {
			error = "Failed to initialize nice (" + error + ")";
			return false;
		}
	}

	{
		this->dtls = make_unique<pipes::DTLS>();
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_IN, true);
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
		this->dtls->logger(this->config->logger);

		this->dtls->callback_data([&](const string& data) {
			LOG_VERBOSE(this->config->logger, "PeerConnection::sctp", "incoming %i bytes", data.length());
			this->sctp->process_incoming_data(data);
		});
		this->dtls->callback_write([&](const string& data) { this->nice->send_data(this->nice->stream_id(), 1, data); });
		this->dtls->callback_error([&](int code, const std::string& error) {
			LOG_ERROR(this->config->logger, "PeerConnection::dtls", "Got error (%i): %s", code, error.c_str());
		});
		this->dtls->callback_initialized = [&](){
			LOG_DEBUG(this->config->logger, "PeerConnection::dtls", "Initialized!");
			std::thread([&]{
				if(!this->sctp->connect()) {
					LOG_ERROR(this->config->logger, "PeerConnection::sctp", "Failed to connect");
					this->trigger_setup_fail(ConnectionComponent::SCTP, "failed to connect");
				} else
					LOG_DEBUG(this->config->logger, "PeerConnection::sctp", "successful connected");
			}).detach();
		};

		auto certificate = pipes::DTLSCertificate::generate("DataPipes", 365);
		if(!this->dtls->initialize(error, certificate)) {
			error = "Failed to initialize dtls (" + error + ")";
			return false;
		}
	}

	{
		this->sctp = make_unique<pipes::SCTP>(this->config->sctp.local_port);
		this->sctp->direct_process(pipes::PROCESS_DIRECTION_IN, true);
		this->sctp->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
		this->sctp->logger(this->config->logger);

		this->sctp->callback_notification = [&](union sctp_notification* event) { this->handle_sctp_event(event); };
		this->sctp->callback_data([&](const pipes::SCTPMessage& message) { this->handle_sctp_message(message); });

		this->sctp->callback_error([&](int code, const std::string& error) {
			LOG_ERROR(this->config->logger, "PeerConnection::sctp", "Got error (%i): %s", code, error.c_str());
		});
		this->sctp->callback_write([&](const std::string& data) {
			LOG_VERBOSE(this->config->logger, "PeerConnection::sctp", "outgoing %i bytes", data.length());
			this->dtls->send(data);
		});

		if(!this->sctp->initialize(error)) {
			error = "Failed to initialize sctp (" + error + ")";
			return false;
		}
	}

	return true;
}

bool PeerConnection::apply_offer(std::string& error, const std::string &sdp) {
	std::stringstream ss(sdp);
	std::string line;

	while (std::getline(ss, line)) {
		if (g_str_has_prefix(line.c_str(), "a=setup:")) {
			std::size_t pos = line.find(":") + 1;
			std::string setup = line.substr(pos);
			if (setup == "active" && this->role == Client) {
				this->role = Server;
			} else if (setup == "passive" && this->role == Server) {
				this->role = Client;
			} else {  // actpass
				// nothing to do
			}
		} else if (g_str_has_prefix(line.c_str(), "a=mid:")) {
			std::size_t pos = line.find(":") + 1;
			std::size_t end = line.find("\r");
			this->mid = line.substr(pos, end - pos);
		} else if (line.find("m=application") == 0) {
			auto last = line.find_last_of(' ');
			if(last == string::npos) {
				error = "invalid m=application";
				return false;
			}
			auto port_string = line.substr(last);
			try {
				this->sctp->remote_port(static_cast<uint16_t>(stoi(port_string)));
			} catch (std::exception& ex) {
				error = "Invalid remote port!";
				return false;
			}
		}
	}

	return nice->apply_remote_sdp(error, sdp);
}

int PeerConnection::apply_ice_candidates(const std::deque<std::string>& candidates) {
	return this->nice->apply_remote_ice_candidates(candidates);
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

	sdp << "v=0\r\n";
	sdp << "o=- " << session_id << " 2 IN IP4 0.0.0.0\r\n";  // Session ID
	sdp << "s=-\r\n";
	sdp << "t=0 0\r\n";
	sdp << "a=msid-semantic: WMS\r\n";
	sdp << "m=application 9 DTLS/SCTP " + to_string(this->sctp->local_port()) + "\r\n";
	sdp << "c=IN IP4 0.0.0.0\r\n";
	sdp << this->nice->generate_local_sdp(candidates);
	sdp << "a=fingerprint:sha-256 " << dtls->getCertificate()->getFingerprint() << "\r\n";
	sdp << "a=ice-options:trickle\r\n";
	sdp << "a=setup:" << (this->role == Client ? "active" : "passive") << "\r\n";
	sdp << "a=mid:" << this->mid << "\r\n";
	sdp << "a=sctpmap:5000 webrtc-datachannel 1024\r\n";

	return sdp.str();
}

void PeerConnection::on_nice_ready() {
	//This is within the main gloop!
	LOG_DEBUG(this->config->logger, "PeerConnection::nice", "successful connected");
}

void PeerConnection::sendSctpMessage(const pipes::SCTPMessage &message) {
	this->sctp->send(message);
}

//TODO error handling right!
void PeerConnection::handle_sctp_event(union sctp_notification* event) {
	switch (event->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_ASSOC_CHANGE)");
			break;
		case SCTP_PEER_ADDR_CHANGE:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_PEER_ADDR_CHANGE)");
			break;
		case SCTP_REMOTE_ERROR:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_REMOTE_ERROR)");
			break;
		case SCTP_SEND_FAILED_EVENT:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_SEND_FAILED_EVENT)");
			break;
		case SCTP_SHUTDOWN_EVENT:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_SHUTDOWN_EVENT)");
			break;
		case SCTP_ADAPTATION_INDICATION:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_ADAPTATION_INDICATION)");
			break;
		case SCTP_PARTIAL_DELIVERY_EVENT:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_PARTIAL_DELIVERY_EVENT)");
			break;
		case SCTP_AUTHENTICATION_EVENT:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_AUTHENTICATION_EVENT)");
			break;
		case SCTP_SENDER_DRY_EVENT:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_SENDER_DRY_EVENT)");
			break;
		case SCTP_NOTIFICATIONS_STOPPED_EVENT:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_NOTIFICATIONS_STOPPED_EVENT)");
			break;
		case SCTP_STREAM_RESET_EVENT:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_STREAM_RESET_EVENT)");
			this->handle_event_stream_reset(event->sn_strreset_event);
			break;
		case SCTP_ASSOC_RESET_EVENT:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_ASSOC_RESET_EVENT)");
			break;
		case SCTP_STREAM_CHANGE_EVENT:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=SCTP_STREAM_CHANGE_EVENT)");
			break;
		default:
			LOG_DEBUG(this->config->logger, "PeerConnection::handle_sctp_event", "OnNotification(type=%s (unknown))", event->sn_header.sn_type);
			break;
	}
}

void PeerConnection::send_sctp_event(uint16_t channel_id, union sctp_notification* event) {
	this->sendSctpMessage({string((const char*) event, event->sn_header.sn_length), channel_id, MSG_NOTIFICATION});
}

void PeerConnection::handle_event_stream_reset(struct sctp_stream_reset_event &ev) {
	deque<shared_ptr<DataChannel>> affected_channels;

	auto nelements = (ev.strreset_length - sizeof(ev)) / sizeof(uint16_t);
	if(nelements == 0) {
		for(const auto& entry : this->active_channels)
			affected_channels.push_back(entry.second);
	} else {
		size_t index = 0;
		while(index < nelements)
			affected_channels.push_back(this->find_datachannel(ev.strreset_stream_list[index++]));
	}
	size_t index = 0;
	for(const auto& channel : affected_channels) {
		if(!channel) {
			index++;
			continue;
		}

		channel->read &= (ev.strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) == 0;
		channel->write &= (ev.strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) == 0;

		LOG_VERBOSE(this->config->logger, "PeerConnection::handle_event_stream_reset", "Resetting channel %i (Read: %i Write: %i)", channel->id(), channel->read, channel->write);
		if(!channel->read && !channel->write) {
			if(channel->callback_close)
				channel->callback_close();
			this->active_channels.erase(channel->id());
		}
	}
}

void PeerConnection::handle_sctp_message(const pipes::SCTPMessage &message) {
	LOG_VERBOSE(this->config->logger, "PeerConnection::handle_sctp_message", "got new message of type %i for channel %i", message.ppid, message.channel_id);
	if (message.ppid == PPID_CONTROL) {
		if (message.data[0] == DC_TYPE_OPEN) {
			this->handle_datachannel_new(message.channel_id, message.data.substr(1));
		} else if (message.data[0] == DC_TYPE_ACK) {
			this->handle_datachannel_ack(message.channel_id);
		} else {
			LOG_ERROR(this->config->logger, "PeerConnection::handle_sctp_message", "Invalid control packet type (%i)", (int) message.data[0]);
		}
	} else if(message.ppid == PPID_STRING || message.ppid == PPID_STRING_EMPTY || message.ppid == PPID_BINARY || message.ppid == PPID_BINARY_EMPTY)
		this->handle_datachannel_message(message.channel_id, message.ppid, message.data);
}

struct dc_new_header {
	uint8_t channel_type;
	uint16_t priority;
	uint32_t reliability;
	uint16_t length_label;
	uint16_t length_protocol;
} __attribute__((packed, aligned(1)));

struct dc_new {
	dc_new_header header;
	std::string label;
	std::string protocol;
};


void PeerConnection::handle_datachannel_new(uint16_t channel_id, const std::string &message) {
	if(this->active_channels.size() >= this->config->max_data_channels) { return; } //TODO error?
	if(sizeof(dc_new_header) > message.length()) return;

	dc_new packet{};
	packet.header.channel_type = (uint8_t) message[0];
	packet.header.priority = be2le16(message.data(), 1);
	packet.header.reliability = be2le32(message.data(), 3);
	packet.header.length_label = be2le16(message.data(), 7);
	packet.header.length_protocol = be2le16(message.data(), 9);


	if(sizeof(packet.header) + packet.header.length_label + packet.header.length_protocol != message.size())
		return;

	packet.label = message.substr(sizeof(packet.header), packet.header.length_label);
	packet.protocol = message.substr(sizeof(packet.header) + packet.header.length_label, packet.header.length_protocol);

	auto channel = shared_ptr<DataChannel>(new DataChannel(this, channel_id, packet.label, packet.protocol));
	this->active_channels[channel_id] = channel;

	if(this->callback_datachannel_new)
		this->callback_datachannel_new(channel);

	char buffer[1];
	buffer[0] = DC_TYPE_ACK;
	this->sendSctpMessage({string(buffer, 1), channel_id, PPID_CONTROL}); //Acknowledge the shit

	LOG_INFO(this->config->logger, "PeerConnection::handle_datachannel_new", "Recived new data channel. Label: %s (Protocol: %s) ChannelId: %i (Type: %i)", packet.label.c_str(), packet.protocol.c_str(), channel_id, packet.header.channel_type);
}

void PeerConnection::handle_datachannel_ack(uint16_t channel_id) {
	//TODO acknowledge for create
}

void PeerConnection::handle_datachannel_message(uint16_t channel_id, uint32_t type, const std::string &message) {
	auto channel = this->find_datachannel(channel_id);
	if(!channel) return; //TODO error handling?

	if(type == PPID_STRING || type == PPID_STRING_EMPTY) {
		if(channel->callback_text)
			channel->callback_text(message);
	} else {
		if(channel->callback_binary)
			channel->callback_binary(message);
	}
}

std::shared_ptr<DataChannel> PeerConnection::find_datachannel(uint16_t channel_id) {
	for(const auto& entry : this->active_channels)
		if(entry.first == channel_id)
			return entry.second;

	return nullptr;
}

std::shared_ptr<DataChannel> PeerConnection::find_datachannel(const std::string &name) {
	for(const auto& entry : this->active_channels)
		if(entry.second->_lable == name)
			return entry.second;

	return nullptr;
}

void PeerConnection::close_datachannel(rtc::DataChannel *channel) {
	//TODO close the channel for the remote as well
	/*
	{
		auto response_length = sizeof(sctp_stream_reset_event) + 2;
		auto response = (sctp_stream_reset_event*) malloc(response_length);
		response->strreset_length = response_length;
		response->strreset_flags = SCTP_STREAM_RESET_INCOMING_SSN;
		response->strreset_assoc_id = 3;
		response->strreset_stream_list[0] = channel->id();
		response->strreset_type = SCTP_STREAM_RESET_EVENT;
		this->send_sctp_event(channel->id(), reinterpret_cast<sctp_notification *>(response));
		free(response);
	}

	{
		auto response_length = sizeof(sctp_stream_reset_event) + 2;
		auto response = (sctp_stream_reset_event*) malloc(response_length);
		response->strreset_length = response_length;
		response->strreset_flags = SCTP_STREAM_RESET_OUTGOING_SSN;
		response->strreset_assoc_id = 3;
		response->strreset_stream_list[0] = channel->id();
		response->strreset_type = SCTP_STREAM_RESET_EVENT;
		this->send_sctp_event(channel->id(), reinterpret_cast<sctp_notification *>(response));
		free(response);
	}
	*/

	if(channel->callback_close)
		channel->callback_close();

	this->active_channels.erase(channel->id()); //Pointer could getting invalid after this

}

void PeerConnection::trigger_setup_fail(rtc::PeerConnection::ConnectionComponent comp, const std::string &reason) {
	if(this->callback_setup_fail)
		this->callback_setup_fail(comp, reason);
}