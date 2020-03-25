#include "pipes/rtc/channels/ApplicationChannel.h"
#include "pipes/rtc/PeerConnection.h"
#include "pipes/tls.h"
#include "pipes/sctp.h"
#include "pipes/misc/logger.h"
#include "pipes/misc/endianness.h"
#include "../json_guard.h"

#include <sstream>

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

#define TEST_AV_TYPE(json, key, type, action, ...) \
if(json.count(key) <= 0) { \
	LOG_ERROR(this->config->logger, __VA_ARGS__); \
	action; \
} \
if(!json[key].type()) { \
	LOG_ERROR(this->config->logger, __VA_ARGS__); \
	action; \
}

uint16_t DataChannel::id() const { return this->_id; }
std::string DataChannel::protocol() const { return this->_protocol; }
std::string DataChannel::lable() const { return this->_lable; }
DataChannel::DataChannel(ApplicationChannel* owner, uint16_t id, std::string lable, std::string protocol) : owner(owner), _id(id), _lable(std::move(lable)), _protocol(std::move(protocol)) {}

void DataChannel::send(const pipes::buffer_view &message, rtc::DataChannel::MessageType type) {
	int ppid_type = 0;
	if(type == DataChannel::BINARY)
		ppid_type = message.empty() ? PPID_BINARY_EMPTY : PPID_BINARY;
	else if(type == DataChannel::TEXT)
		ppid_type = message.empty() ? PPID_STRING_EMPTY : PPID_STRING;
	else {
		return; //Should nevber happen
	}
	this->owner->send_sctp({message, this->id(), (uint32_t) ppid_type});
}

void DataChannel::close() {
	this->owner->close_datachannel(this);
}

ApplicationChannel::ApplicationChannel(PeerConnection* owner, rtc::NiceStreamId id, const shared_ptr<rtc::ApplicationChannel::Configuration> &config) : Channel(owner, id), config(config) { }
ApplicationChannel::~ApplicationChannel() {
	string error;
	this->reset(error);
}

bool ApplicationChannel::initialize(std::string &error) {
    this->sctp = make_unique<pipes::SCTP>(this->config->local_port);
    this->sctp->direct_process(pipes::PROCESS_DIRECTION_IN, true);
    this->sctp->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
    this->sctp->logger(this->config->logger);

    this->sctp->callback_notification = [&](union sctp_notification* event) { this->handle_sctp_event(event); };
    this->sctp->callback_data([&](const pipes::SCTPMessage& message) { this->handle_sctp_message(message); });

    this->sctp->callback_error([&](int code, const std::string& error) {
        LOG_ERROR(this->config->logger, "ApplicationStream::sctp", "Got error (%i): %s", code, error.c_str());
    });
    this->sctp->callback_write([&](const pipes::buffer_view& data) {
        LOG_VERBOSE(this->config->logger, "ApplicationStream::sctp", "outgoing %i bytes", data.length());
        this->send_data(data, true);
    });

    if(!this->sctp->initialize(error)) {
        error = "Failed to initialize sctp (" + error + ")";
        return false;
    }

	return true;
}

void ApplicationChannel::on_dtls_initialized(const std::shared_ptr<DTLSHandler>&handle) {
	LOG_DEBUG(this->config->logger, "ApplicationStream::dtls", "Initialized! Starting SCTP connect");
	if(!this->sctp->connect()) {
		LOG_ERROR(this->config->logger, "ApplicationStream::sctp", "Failed to connect");
		//this->trigger_setup_fail(ConnectionComponent::SCTP, "failed to connect");
		//FIXME!
	} else
		LOG_DEBUG(this->config->logger, "ApplicationStream::sctp", "successful connected");
}

bool ApplicationChannel::apply_sdp(const json_guard &, const json_guard &media_entry) {
	{
		TEST_AV_TYPE(media_entry, "mid", is_string, return false, "ApplicationStream::apply_sdp", "Entry contains invalid/missing id");
		this->mid = media_entry["mid"];
		LOG_DEBUG(this->config->logger, "ApplicationStream::apply_offer", "Got mid type %s", this->mid.c_str());
	}

	{
		uint16_t sctp_port = 5000;

		if(media_entry.count("payloads") > 0) {
			string payload = media_entry["payloads"];
			if(payload.find_first_not_of("0123456789") == string::npos) {
				sctp_port = static_cast<uint16_t>(stoi(payload));
			} else
				LOG_DEBUG(this->config->logger, "ApplicationStream::apply_sdp", "Ignoring payload %s", payload.c_str());
			this->external_sctp_port = false;
		}
		if(media_entry.count("sctp-port") > 0) {
			this->external_sctp_port = true;
			TEST_AV_TYPE(media_entry, "sctp-port", is_number, return false, "ApplicationStream::apply_sdp", "Invalid port!");
			sctp_port = media_entry["sctp-port"];
		}
		this->sctp->remote_port(sctp_port);
		LOG_DEBUG(this->config->logger, "ApplicationStream::apply_sdp", "Apply sctp port %u", sctp_port);
	}

	return true;
}

std::string ApplicationChannel::generate_sdp() {
	std::ostringstream sdp;
	sdp << "m=application 9 DTLS/SCTP " + to_string(this->sctp->local_port()) + "\r\n"; //The 9 is the port? https://tools.ietf.org/html/rfc4566#page-22
	sdp << "c=IN IP4 0.0.0.0\r\n";

	sdp << "a=mid:" << this->mid << "\r\n";

    sdp << "a=sctpmap:" << to_string(this->sctp->local_port()) << " webrtc-datachannel 1024\r\n";
    //sdp << "a=sctp-port:" << this->sctp->local_port() << "\r\n";

	return sdp.str();
}

bool ApplicationChannel::reset(std::string &) {
	if(this->sctp) this->sctp->finalize();

	return true;
}

bool ApplicationChannel::process_incoming_dtls_data(const pipes::buffer_view &data) {
    this->sctp->process_incoming_data(data);
    return true;
}

bool ApplicationChannel::process_incoming_rtp_data(RTPPacket &) { return false; }
bool ApplicationChannel::process_incoming_rtcp_data(RTCPPacket &) { return false; }

void ApplicationChannel::send_sctp(const pipes::SCTPMessage &message) {
	this->sctp->send(message);
}

//TODO error handling right!
void ApplicationChannel::handle_sctp_event(union sctp_notification* event) {
	switch (event->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_ASSOC_CHANGE)");
			break;
		case SCTP_PEER_ADDR_CHANGE:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_PEER_ADDR_CHANGE)");
			break;
		case SCTP_REMOTE_ERROR:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_REMOTE_ERROR)");
			break;
		case SCTP_SEND_FAILED_EVENT:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_SEND_FAILED_EVENT)");
			break;
		case SCTP_SHUTDOWN_EVENT:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_SHUTDOWN_EVENT)");
			break;
		case SCTP_ADAPTATION_INDICATION:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_ADAPTATION_INDICATION)");
			break;
		case SCTP_PARTIAL_DELIVERY_EVENT:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_PARTIAL_DELIVERY_EVENT)");
			break;
		case SCTP_AUTHENTICATION_EVENT:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_AUTHENTICATION_EVENT)");
			break;
		case SCTP_SENDER_DRY_EVENT:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_SENDER_DRY_EVENT)");
			break;
		case SCTP_NOTIFICATIONS_STOPPED_EVENT:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_NOTIFICATIONS_STOPPED_EVENT)");
			break;
		case SCTP_STREAM_RESET_EVENT:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_STREAM_RESET_EVENT)");
			this->handle_event_stream_reset(event->sn_strreset_event);
			break;
		case SCTP_ASSOC_RESET_EVENT:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_ASSOC_RESET_EVENT)");
			break;
		case SCTP_STREAM_CHANGE_EVENT:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=SCTP_STREAM_CHANGE_EVENT)");
			break;
		default:
			LOG_DEBUG(this->config->logger, "ApplicationStream::handle_sctp_event", "OnNotification(type=%s (unknown))", event->sn_header.sn_type);
			break;
	}
}

void ApplicationChannel::send_sctp_event(uint16_t channel_id, union sctp_notification* event) {
	this->send_sctp({pipes::buffer_view{(void *) event, event->sn_header.sn_length}, channel_id, MSG_NOTIFICATION});
}

void ApplicationChannel::handle_event_stream_reset(struct sctp_stream_reset_event &ev) {
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

		LOG_VERBOSE(this->config->logger, "ApplicationStream::handle_event_stream_reset", "Resetting channel %i (Read: %i Write: %i)", channel->id(), channel->read, channel->write);
		if(!channel->read && !channel->write) {
			if(channel->callback_close)
				channel->callback_close();
			this->active_channels.erase(channel->id());
		}
	}
}

void ApplicationChannel::handle_sctp_message(const pipes::SCTPMessage &message) {
	LOG_VERBOSE(this->config->logger, "ApplicationStream::handle_sctp_message", "got new message of type %i for channel %i", message.ppid, message.channel_id);
	if (message.ppid == PPID_CONTROL) {
		if (message.data[0] == DC_TYPE_OPEN) {
			this->handle_datachannel_new(message.channel_id, message.data.view(1));
		} else if (message.data[0] == DC_TYPE_ACK) {
			this->handle_datachannel_ack(message.channel_id);
		} else {
			LOG_ERROR(this->config->logger, "ApplicationStream::handle_sctp_message", "Invalid control packet type (%i)", (int) message.data[0]);
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


void ApplicationChannel::handle_datachannel_new(uint16_t channel_id, const pipes::buffer_view &message) {
	if(this->active_channels.size() >= this->config->max_data_channels) { return; } //TODO error?
	if(sizeof(dc_new_header) > message.length()) return;

	dc_new packet{};
	packet.header.channel_type = (uint8_t) message[0];
	packet.header.priority = be2le16((char*) message.data_ptr(), 1);
	packet.header.reliability = be2le32((char*) message.data_ptr(), 3);
	packet.header.length_label = be2le16((char*) message.data_ptr(), 7);
	packet.header.length_protocol = be2le16((char*) message.data_ptr(), 9);


	if(sizeof(packet.header) + packet.header.length_label + packet.header.length_protocol != message.length())
		return;

	packet.label = message.view(sizeof(packet.header), packet.header.length_label).string();
	packet.protocol = message.view(sizeof(packet.header) + packet.header.length_label, packet.header.length_protocol).string();

	auto channel = shared_ptr<DataChannel>(new DataChannel(this, channel_id, packet.label, packet.protocol));
	this->active_channels[channel_id] = channel;

	if(this->callback_datachannel_new)
		this->callback_datachannel_new(channel);

	char buffer[1];
	buffer[0] = DC_TYPE_ACK;
	this->send_sctp({pipes::buffer_view(buffer, 1), channel_id, PPID_CONTROL}); //Acknowledge the shit

	LOG_INFO(this->config->logger, "ApplicationStream::handle_datachannel_new", "Recived new data channel. Label: %s (Protocol: %s) ChannelId: %i (Type: %i)", packet.label.c_str(), packet.protocol.c_str(), channel_id, packet.header.channel_type);
}

void ApplicationChannel::handle_datachannel_ack(uint16_t channel_id) {
	//TODO acknowledge for create
}

void ApplicationChannel::handle_datachannel_message(uint16_t channel_id, uint32_t type, const pipes::buffer_view &message) {
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

std::shared_ptr<DataChannel> ApplicationChannel::find_datachannel(uint16_t channel_id) {
	for(const auto& entry : this->active_channels)
		if(entry.first == channel_id)
			return entry.second;

	return nullptr;
}

std::shared_ptr<DataChannel> ApplicationChannel::find_datachannel(const std::string &name) {
	for(const auto& entry : this->active_channels)
		if(entry.second->_lable == name)
			return entry.second;

	return nullptr;
}

void ApplicationChannel::close_datachannel(rtc::DataChannel *channel) {
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