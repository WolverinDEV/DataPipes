//
// Created by wolverindev on 03.08.18.
//

#include <sstream>
#include <iostream>
#include <cstring>
#include <include/endianness.h>
#include "include/rtc/PeerConnection.h"

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
DataChannel::DataChannel(PeerConnection* owner, uint16_t id, std::string lable, std::string protocol) : owner(owner), _id(id), _lable(lable), _protocol(protocol) {}

void DataChannel::send(const std::string &message, rtc::DataChannel::MessageType type) {
	this->owner->sendSctpMessage({message, this->id(), type == DataChannel::BINARY ? PPID_BINARY : PPID_STRING});
}

PeerConnection::PeerConnection() { }
PeerConnection::~PeerConnection() {}

bool PeerConnection::initialize(std::string &error) {
	{
		auto config = make_shared<NiceWrapper::Config>();
		config->ice_servers.push_back({"stun.l.google.com", 19302});


		this->nice = make_unique<NiceWrapper>(config);
		this->nice->set_callback_local_candidate([](const std::string& candidate){});
		this->nice->set_callback_ready(bind(&PeerConnection::on_nice_ready, this));
		this->nice->set_callback_recive([&](const std::string& data) {
			cout << "Got nice data: "<< data.length() << endl;
			this->dtls->process_incoming_data(data);
		});
		if(!this->nice->initialize(error)) {
			error = "Failed to initialize nice (" + error + ")";
			return false;
		}
	}

	{
		this->dtls = make_unique<DTLS>();
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_IN, true);
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_OUT, true);

		this->dtls->callback_data([&](const string& data) {
			cout << "Got dts data: " << data.length() << endl;
			this->sctp->process_incoming_data(data);
		});
		this->dtls->callback_write([&](const string& data) {
			cout << "[DTLS] Write to nice: " << data.length() << endl;
			this->nice->send_data(this->nice->stream_id(), 1, data);
		});
		this->dtls->callback_error([&](int code, const std::string& error) {
			cerr << "[DTLS] Got error: " << error << endl;
		});
		this->dtls->callback_initialized = [&](){
			cout << "[CTLS] Initialized!" << endl;
			std::thread([&]{
				if(!this->sctp->connect()) {
					cout << "[SCTP] Failed to connect!" << endl;
				} else
					cout << "[SCTP] Connected!" << endl;
			}).detach();
		};

		auto certificate = DTLSCertificate::generate("DataPipes", 365);
		if(!this->dtls->initialize(error, certificate)) {
			error = "Failed to initialize dtls (" + error + ")";
			return false;
		}
	}

	{
		this->sctp = make_unique<pipes::SCTP>(5000, 5000);
		this->sctp->direct_process(pipes::PROCESS_DIRECTION_IN, true);
		this->sctp->direct_process(pipes::PROCESS_DIRECTION_OUT, true);

		this->sctp->callback_notification = [&](union sctp_notification* event) { this->handle_sctp_event(event); };
		this->sctp->callback_data([&](const pipes::SCTPMessage& message) { this->handle_sctp_message(message); });

		this->sctp->callback_error([&](int code, const std::string& error) {
			cerr << "[SCTP] Got error: " << error << endl;
		});
		this->sctp->callback_write([&](const std::string& data) {
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
	sdp << "m=application 9 DTLS/SCTP 5000\r\n";  //FIXME: hardcoded port
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
	cout << "Nice connected!" << endl;
	std::thread([&]{
		this->dtls->do_handshake();
	}).detach();
}

void PeerConnection::sendSctpMessage(const pipes::SCTPMessage &message) {
	this->sctp->send(message);
}

//TODO make the messages and eror handling right!
#define SPDLOG_TRACE(__unused__, message, ...) cout << message << endl;
void PeerConnection::handle_sctp_event(union sctp_notification* event) {
	switch (event->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_ASSOC_CHANGE)");
			break;
		case SCTP_PEER_ADDR_CHANGE:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_PEER_ADDR_CHANGE)");
			break;
		case SCTP_REMOTE_ERROR:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_REMOTE_ERROR)");
			break;
		case SCTP_SEND_FAILED_EVENT:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_SEND_FAILED_EVENT)");
			break;
		case SCTP_SHUTDOWN_EVENT:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_SHUTDOWN_EVENT)");
			break;
		case SCTP_ADAPTATION_INDICATION:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_ADAPTATION_INDICATION)");
			break;
		case SCTP_PARTIAL_DELIVERY_EVENT:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_PARTIAL_DELIVERY_EVENT)");
			break;
		case SCTP_AUTHENTICATION_EVENT:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_AUTHENTICATION_EVENT)");
			break;
		case SCTP_SENDER_DRY_EVENT:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_SENDER_DRY_EVENT)");
			break;
		case SCTP_NOTIFICATIONS_STOPPED_EVENT:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_NOTIFICATIONS_STOPPED_EVENT)");
			break;
		case SCTP_STREAM_RESET_EVENT:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_STREAM_RESET_EVENT)");
			break;
		case SCTP_ASSOC_RESET_EVENT:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_ASSOC_RESET_EVENT)");
			break;
		case SCTP_STREAM_CHANGE_EVENT:
			SPDLOG_TRACE(logger, "OnNotification(type=SCTP_STREAM_CHANGE_EVENT)");
			break;
		default:
			SPDLOG_TRACE(logger, "OnNotification(type={} (unknown))", notify->sn_header.sn_type);
			break;
	}
}

void PeerConnection::handle_sctp_message(const pipes::SCTPMessage &message) {
	cout << "Got sctp message!" << endl;
	if (message.ppid == PPID_CONTROL) {
		cout << "Got controll ppid on " << message.channel_id << endl;
		if (message.data[0] == DC_TYPE_OPEN) {
			this->handle_datachannel_new(message.channel_id, message.data.substr(1));
		} else if (message.data[0] == DC_TYPE_ACK) {
			cout << "Got message ack!" << endl; //FIXME care about it? And create a method to open data channels?
		} else {
			cerr << "Unknown datachannel controll type (" << (int) message.data[0] << ")" << endl;
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
	if(this->active_channels.size() >= this->_max_data_channels) { return; } //TODO error?
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
	cout << "Got new data channel! Label: " << packet.label << " (" << packet.protocol << "). Channel id " << channel_id << " (Type: " << hex << (uint32_t) (uint8_t) packet.header.channel_type << dec << ")" << endl;
}

void PeerConnection::handle_datachannel_ack(uint16_t, const std::string &) {
	//TODO
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