#include <sstream>
#include "json.hpp"
#include "include/misc/endianness.h"
#include "include/rtc/PeerConnection.h"
#include "include/rtc/ApplicationStream.h"
#include "include/tls.h"
#include "include/sctp.h"

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
DataChannel::DataChannel(ApplicationStream* owner, uint16_t id, std::string lable, std::string protocol) : owner(owner), _id(id), _lable(std::move(lable)), _protocol(std::move(protocol)) {}

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

ApplicationStream::ApplicationStream(PeerConnection* owner, rtc::StreamId id, const shared_ptr<rtc::ApplicationStream::Configuration> &config) : Stream(owner, id), config(config) { }
ApplicationStream::~ApplicationStream() {
	string error;
	this->reset(error);
}

bool ApplicationStream::initialize(std::string &error) {
	if(this->_stream_id > 0) {
		this->dtls = make_unique<pipes::TLS>();
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_IN, true);
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
		this->dtls->logger(this->config->logger);

		this->dtls->callback_data([&](const pipes::buffer_view& data) {
			LOG_VERBOSE(this->config->logger, "ApplicationStream::sctp", "incoming %i bytes", data.length());
			this->sctp->process_incoming_data(data);
		});
		this->dtls->callback_write([&](const pipes::buffer_view& data) {
			LOG_VERBOSE(this->config->logger, "ApplicationStream::dtls", "outgoing %i bytes", data.length());
			this->send_data(data);
		});
		this->dtls->callback_error([&](int code, const std::string& error) {
			LOG_ERROR(this->config->logger, "ApplicationStream::dtls", "Got error (%i): %s", code, error.c_str());
		});
		this->dtls->callback_initialized = [&](){
			this->on_dtls_initialized(this->dtls);
		};

		this->dtls_certificate = pipes::TLSCertificate::generate("DataPipes", 365);
	}

	{
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
			if(this->dtls)
				this->dtls->send(data);
			else {
				this->send_data_merged(data, true);
			}
		});

		if(!this->sctp->initialize(error)) {
			error = "Failed to initialize sctp (" + error + ")";
			return false;
		}
	}

	return true;
}

void ApplicationStream::on_dtls_initialized(const std::unique_ptr<pipes::TLS> &handle) {
	LOG_DEBUG(this->config->logger, "ApplicationStream::dtls", "Initialized! Starting SCTP connect");
	if(!this->sctp->connect()) {
		LOG_ERROR(this->config->logger, "ApplicationStream::sctp", "Failed to connect");
		//this->trigger_setup_fail(ConnectionComponent::SCTP, "failed to connect");
		//FIXME!
	} else
		LOG_DEBUG(this->config->logger, "ApplicationStream::sctp", "successful connected");
}

bool ApplicationStream::apply_sdp(const nlohmann::json &, const nlohmann::json &media_entry) {
	{
		TEST_AV_TYPE(media_entry, "setup", is_string, return false, "ApplicationStream::apply_sdp", "Entry contains invalid/missing setup type");
		string setup_type = media_entry["setup"];
		LOG_VERBOSE(this->config->logger, "ApplicationStream::apply_offer", "Stream setup type: %s", setup_type.c_str());
		if(setup_type == "active")
			this->role = Server;
		else if(setup_type == "passive")
			this->role = Client;
	}

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
		} else if(media_entry.count("sctp-port") > 0) {
			this->external_sctp_port = true;
			TEST_AV_TYPE(media_entry, "sctp-port", is_number, return false, "ApplicationStream::apply_sdp", "Invalid port!");
			sctp_port = media_entry["sctp-port"];
		}
		this->sctp->remote_port(sctp_port);
		LOG_DEBUG(this->config->logger, "ApplicationStream::apply_sdp", "Apply sctp port %u", sctp_port);
	}

	return true;
}

/*
 {
    "groups": [
        {
            "mids": "audio data",
            "type": "BUNDLE"
        }
    ],
    "media": [
        {
            "connection": {
                "ip": "0.0.0.0",
                "version": 4
            },
            "direction": "recvonly",
            "ext": [
                {
                    "uri": "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
                    "value": 1
                }
            ],
            "fingerprint": {
                "hash": "30:22:19:90:D1:68:3B:61:3C:8B:43:05:A9:6A:5C:EB:FF:91:09:A8:0C:12:A4:2E:60:8C:20:D9:19:D2:EC:B6",
                "type": "sha-256"
            },
            "fmtp": [
                {
                    "config": "minptime=10;useinbandfec=1",
                    "payload": 111
                }
            ],
            "iceOptions": "trickle",
            "icePwd": "rttC8j09TxW7O/KtpUp+oV18",
            "iceUfrag": "LAcb",
            "mid": "audio",
            "payloads": "111 103 104 9 0 8 106 105 13 110 112 113 126",
            "port": 9,
            "protocol": "UDP/TLS/RTP/SAVPF",
            "rtcp": {
                "address": "0.0.0.0",
                "ipVer": 4,
                "netType": "IN",
                "port": 9
            },
            "rtcpFb": [
                {
                    "payload": "111",
                    "type": "transport-cc"
                }
            ],
            "rtcpMux": "rtcp-mux",
            "rtp": [
                {
                    "codec": "opus",
                    "encoding": "2",
                    "payload": 111,
                    "rate": 48000
                },
                {
                    "codec": "ISAC",
                    "payload": 103,
                    "rate": 16000
                },
                {
                    "codec": "ISAC",
                    "payload": 104,
                    "rate": 32000
                },
                {
                    "codec": "G722",
                    "payload": 9,
                    "rate": 8000
                },
                {
                    "codec": "PCMU",
                    "payload": 0,
                    "rate": 8000
                },
                {
                    "codec": "PCMA",
                    "payload": 8,
                    "rate": 8000
                },
                {
                    "codec": "CN",
                    "payload": 106,
                    "rate": 32000
                },
                {
                    "codec": "CN",
                    "payload": 105,
                    "rate": 16000
                },
                {
                    "codec": "CN",
                    "payload": 13,
                    "rate": 8000
                },
                {
                    "codec": "telephone-event",
                    "payload": 110,
                    "rate": 48000
                },
                {
                    "codec": "telephone-event",
                    "payload": 112,
                    "rate": 32000
                },
                {
                    "codec": "telephone-event",
                    "payload": 113,
                    "rate": 16000
                },
                {
                    "codec": "telephone-event",
                    "payload": 126,
                    "rate": 8000
                }
            ],
            "setup": "actpass",
            "type": "audio"
        },
        {
            "connection": {
                "ip": "0.0.0.0",
                "version": 4
            },
            "fingerprint": {
                "hash": "30:22:19:90:D1:68:3B:61:3C:8B:43:05:A9:6A:5C:EB:FF:91:09:A8:0C:12:A4:2E:60:8C:20:D9:19:D2:EC:B6",
                "type": "sha-256"
            },
            "fmtp": [],
            "iceOptions": "trickle",
            "icePwd": "rttC8j09TxW7O/KtpUp+oV18",
            "iceUfrag": "LAcb",
            "mid": "data",
            "payloads": "5000", //This is may send as sctp-port
            "sctp-port": 5000

            "port": 9,
            "protocol": "DTLS/SCTP",
            "rtp": [],
            "sctpmap": {
                "app": "webrtc-datachannel",
                "maxMessageSize": 1024,
                "sctpmapNumber": 5000
            },
            "setup": "actpass",
            "type": "application"
        }
    ],
    "msidSemantic": {
        "token": "WMS"
    },
    "name": "-",
    "origin": {
        "address": "127.0.0.1",
        "ipVer": 4,
        "netType": "IN",
        "sessionId": 8133322930326912268,
        "sessionVersion": 2,
        "username": "-"
    },
    "timing": {
        "start": 0,
        "stop": 0
    },
    "version": 0
}

v=0\r\no=- 8133322930326912268 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE audio data
a=msid-semantic: WMS
m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:LAcb
a=ice-pwd:rttC8j09TxW7O/KtpUp+oV18
a=ice-options:trickle
a=fingerprint:sha-256 30:22:19:90:D1:68:3B:61:3C:8B:43:05:A9:6A:5C:EB:FF:91:09:A8:0C:12:A4:2E:60:8C:20:D9:19:D2:EC:B6
a=setup:actpass
a=mid:audio
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=recvonly
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=rtpmap:103 ISAC/16000
a=rtpmap:104 ISAC/32000
a=rtpmap:9 G722/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:106 CN/32000
a=rtpmap:105 CN/16000
a=rtpmap:13 CN/8000
a=rtpmap:110 telephone-event/48000
a=rtpmap:112 telephone-event/32000
a=rtpmap:113 telephone-event/16000
a=rtpmap:126 telephone-event/8000
m=application 9 DTLS/SCTP 5000
c=IN IP4 0.0.0.0
a=ice-ufrag:LAcb
a=ice-pwd:rttC8j09TxW7O/KtpUp+oV18
a=ice-options:trickle
a=fingerprint:sha-256 30:22:19:90:D1:68:3B:61:3C:8B:43:05:A9:6A:5C:EB:FF:91:09:A8:0C:12:A4:2E:60:8C:20:D9:19:D2:EC:B6
a=setup:actpass
a=mid:data
a=sctpmap:5000 webrtc-datachannel 1024

 */

std::string ApplicationStream::generate_sdp() {
	ostringstream sdp;
	sdp << "m=application 9 DTLS/SCTP " + to_string(this->sctp->local_port()) + "\r\n"; //The 9 is the port? https://tools.ietf.org/html/rfc4566#page-22
	sdp << "c=IN IP4 0.0.0.0\r\n";

	if(this->dtls) {
		if(this->dtls_certificate)
			sdp << "a=fingerprint:sha-256 " << this->dtls_certificate->getFingerprint() << "\r\n";
		else
			sdp << "a=fingerprint:sha-256 " << dtls->getCertificate()->getFingerprint() << "\r\n";
	}
	sdp << "a=setup:" << (this->role == Client ? "active" : "passive") << "\r\n";
	sdp << "a=mid:" << this->mid << "\r\n";
	sdp << "a=sctpmap:" << to_string(this->sctp->local_port()) << " webrtc-datachannel 1024\r\n";

	if(this->external_sctp_port)
		sdp << "a=sctp-port:" << this->sctp->local_port() << "\r\n";

	return sdp.str();
}

bool ApplicationStream::reset(std::string &) {
	if(this->sctp) this->sctp->finalize();
	if(this->dtls) this->dtls->finalize();

	return true;
}

void ApplicationStream::process_incoming_data(const pipes::buffer_view &data) {
	if(this->dtls)
		this->dtls->process_incoming_data(data);
	else
		this->sctp->process_incoming_data(data);
}

void ApplicationStream::send_sctp(const pipes::SCTPMessage &message) {
	this->sctp->send(message);
}

//TODO error handling right!
void ApplicationStream::handle_sctp_event(union sctp_notification* event) {
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

void ApplicationStream::send_sctp_event(uint16_t channel_id, union sctp_notification* event) {
	this->send_sctp({pipes::buffer_view{(void *) event, event->sn_header.sn_length}, channel_id, MSG_NOTIFICATION});
}

void ApplicationStream::handle_event_stream_reset(struct sctp_stream_reset_event &ev) {
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

void ApplicationStream::handle_sctp_message(const pipes::SCTPMessage &message) {
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


void ApplicationStream::handle_datachannel_new(uint16_t channel_id, const pipes::buffer_view &message) {
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

void ApplicationStream::handle_datachannel_ack(uint16_t channel_id) {
	//TODO acknowledge for create
}

void ApplicationStream::handle_datachannel_message(uint16_t channel_id, uint32_t type, const pipes::buffer_view &message) {
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

std::shared_ptr<DataChannel> ApplicationStream::find_datachannel(uint16_t channel_id) {
	for(const auto& entry : this->active_channels)
		if(entry.first == channel_id)
			return entry.second;

	return nullptr;
}

std::shared_ptr<DataChannel> ApplicationStream::find_datachannel(const std::string &name) {
	for(const auto& entry : this->active_channels)
		if(entry.second->_lable == name)
			return entry.second;

	return nullptr;
}

void ApplicationStream::close_datachannel(rtc::DataChannel *channel) {
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

void ApplicationStream::on_nice_ready() {
	if(this->dtls) {
		LOG_DEBUG(this->config->logger, "ApplicationStream::on_nice_ready", "Nice stream has been initialized successfully. Initializing DTLS as %s", this->role == Role::Client ? "client" : "server");

		string error;
		if(!this->dtls->initialize(error, this->dtls_certificate, pipes::DTLS_v1_2,this->role == Role::Client ? pipes::SSL::CLIENT : pipes::SSL::SERVER, [](SSL_CTX* ctx) {
			SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32"); //Required for rt(c)p
			return true;
		})) {
			LOG_ERROR(this->config->logger, "ApplicationStream::on_nice_ready", "Failed to initialize DTLS (%s)", error.c_str());
			return;
		}



		if(this->role == Role::Client) {
			if(!this->dtls->do_handshake()) {
				LOG_ERROR(this->config->logger, "ApplicationStream::on_nice_ready", "Failed to process dtls handshake!");
			}
		}
	}
	this->resend_buffer(true);
}