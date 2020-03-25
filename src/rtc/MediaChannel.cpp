#include "pipes/rtc/channels/MediaChannel.h"
#include "pipes/misc/endianness.h"
#include "pipes/rtc/PeerConnection.h"
#include "pipes/sctp.h"
#include "pipes/rtc/DTLSHandler.h"
#include "pipes/rtc/RTPPacket.h"

#include <sstream>
#include <openssl/srtp.h>
#include <cinttypes> //For printf
#include <utility>
#include <glib.h>

#include "json_guard.h"

#if defined(SRTP_VERSION_1)
    #include <srtp/srtp.h>

    #define srtp_err_status_t err_status_t
    #define srtp_err_status_ok err_status_ok
    #define srtp_err_status_replay_fail err_status_replay_fail
    #define srtp_err_status_replay_old err_status_replay_old

    #define srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32 crypto_policy_set_aes_cm_128_hmac_sha1_32
    #define srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80 crypto_policy_set_aes_cm_128_hmac_sha1_80
    #define srtp_crypto_policy_set_aes_gcm_256_16_auth crypto_policy_set_aes_gcm_256_16_auth
    #define srtp_crypto_policy_set_aes_gcm_128_16_auth crypto_policy_set_aes_gcm_128_16_auth
#elif defined(SRTP_VERSION_1)
    #include <srtp2/srtp.h>
#elif defined(SRTP_BUNDLED)
    #include <srtp.h>
#else
    #error "Invalid SRTP version!"
#endif

/* SRTP stuff (http://tools.ietf.org/html/rfc3711) */
#define SRTP_MASTER_KEY_LENGTH	(128 / 8) // => 16 bytes (128 bits)
#define SRTP_MASTER_SALT_LENGTH	(112 / 8) // => 12 bytes (112 bits)

#define SRTP_MASTER_LENGTH (SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH)

/* AES-GCM stuff (http://tools.ietf.org/html/rfc7714) */
#define SRTP_AESGCM128_MASTER_KEY_LENGTH	16
#define SRTP_AESGCM128_MASTER_SALT_LENGTH	12
#define SRTP_AESGCM128_MASTER_LENGTH (SRTP_AESGCM128_MASTER_KEY_LENGTH + SRTP_AESGCM128_MASTER_SALT_LENGTH)
#define SRTP_AESGCM256_MASTER_KEY_LENGTH	32
#define SRTP_AESGCM256_MASTER_SALT_LENGTH	12
#define SRTP_AESGCM256_MASTER_LENGTH (SRTP_AESGCM256_MASTER_KEY_LENGTH + SRTP_AESGCM256_MASTER_SALT_LENGTH)

#define SRTP_MAX_MASTER_LENGTH (SRTP_AESGCM256_MASTER_LENGTH)

#define TEST_AV_TYPE(json, key, type, action, ...)  \
if(json.count(key) <= 0) {                          \
	LOG_ERROR(this->config->logger, __VA_ARGS__);   \
	action;                                         \
}                                                   \
if(!json[key].type()) {                             \
	LOG_ERROR(this->config->logger, __VA_ARGS__);   \
	action;                                         \
}

using namespace std;
using namespace std::chrono;
using namespace rtc;
using namespace rtc::codec;

std::shared_ptr<Codec> codec::create(const json_guard& sdp) {
	if(sdp.count("codec") <= 0 || !sdp["codec"].is_string()) return nullptr;
	if(sdp.count("payload") <= 0 || !sdp["payload"].is_number()) return nullptr;

	cout << "OP: " << sdp.dump() << endl;
	std::shared_ptr<Codec> result;

	//TODO implement more codecs
	if(sdp["codec"] == "opus") {
		if(sdp.count("encoding") <= 0 || !sdp["encoding"].is_string()) return nullptr;

		result = make_shared<OpusCodec>();
		result->type = Codec::OPUS;
		static_pointer_cast<OpusCodec>(result)->encoding = stol((string) sdp["encoding"]);
	}

	if(!result)
		result = make_shared<UnknownCodec>();

	if(!result->type)
		result->type = Codec::UNKNOWN;

	result->id = sdp["payload"];
	result->codec = sdp["codec"];

	if(sdp.count("rate") > 0)
		result->rate = sdp["rate"];

	return result;
}

bool Codec::local_accepted() {
	return this->accepted;
}

bool UnknownCodec::write_sdp(std::ostringstream &os) {
	if(!this->write_sdp_fmtp(os)) {
        return false;
	}
    if(!this->write_sdp_rtpmap(os)) {
        return false;
    }
	return this->write_local_parameters(os);
}

bool UnknownCodec::write_sdp_rtpmap(std::ostringstream &os) {
	/* we need a=fmtp:97 apt=96 */
	os << "a=rtpmap:" << (uint32_t) this->id << " " << this->codec;

	if(this->rate > 0)
		os << "/" << this->rate;

	os  << endl;
	return true;
}

bool UnknownCodec::write_sdp_fmtp(std::ostringstream &os) {
	for(const auto& parameter : this->parameters)
		os << "a=fmtp:" << (uint32_t) this->id << " " << parameter << "\n";
	return true;
}

bool UnknownCodec::write_local_parameters(std::ostringstream &os) {
    for(const auto& [key, values] : this->local_parameters)
        for(const auto& value : values)
            os << "a=" << key << ":" << (uint32_t) this->id << " " << value << "\n";
    return true;
}

bool OpusCodec::write_sdp(std::ostringstream &os) {
	os << "a=rtpmap:" << (uint32_t) this->id << " " << this->codec << "/" << this->rate << "/" << (uint32_t) this->encoding << "\n";
	return this->write_sdp_fmtp(os);
}

std::deque<std::shared_ptr<codec::Codec>> MediaStream::list_codecs() {
	return this->offered_codecs;
}

std::deque<std::shared_ptr<codec::Codec>> MediaStream::find_codecs_by_name(const std::string &name) {
	deque<shared_ptr<codec::Codec>> result;

	for(const auto& codec : this->offered_codecs)
		if(codec->codec == name) result.push_back(codec);

	return result;
}

std::shared_ptr<codec::Codec> MediaStream::find_codec_by_id(const rtc::codec::id_t &id) {
	for(const auto& codec : this->offered_codecs)
		if(codec->id == id)
			return codec;
	return nullptr;
}

std::shared_ptr<MediaChannel> MediaStream::register_local_channel(const std::shared_ptr<codec::Codec> &codec, std::optional<std::string> track_label, std::optional<std::string> stream_label) {
    auto channel = make_shared<MediaChannel>();

    channel->codec = codec;
    channel->local = true;

    while(!channel->ssrc || this->find_track_by_id(channel->ssrc))
        channel->ssrc = (uint8_t) rand();
    channel->id = std::to_string(channel->ssrc);

    channel->track_label = std::move(track_label);
    channel->stream_label = std::move(stream_label);

    this->local_channels.push_back(channel);
    return channel;
}

std::shared_ptr<HeaderExtension> MediaStream::register_local_extension(const std::string &name, const std::string & direction, const std::string & config, uint8_t id) {
	for(const auto& ext : this->local_extensions)
		if(ext->name == name) return ext;

	auto extension = make_shared<HeaderExtension>();
	extension->local = true;
	extension->name = name;
	extension->direction = direction;
	extension->config = config;
	extension->id = id;
	while(extension->id == 0 || this->find_extension_by_id(extension->id, direction::outgoing)) extension->id++;

	this->local_extensions.push_back(extension);
	return extension;
}

std::shared_ptr<MediaChannel> MediaStream::find_track_by_id(uint32_t id, direction::value direction) {
	if((direction & direction::outgoing) > 0) {
		for(const auto& channel : this->local_channels)
			if(channel->ssrc == id) return channel;
	}
	if((direction & direction::incoming) > 0) {
		for(const auto& channel : this->remote_channels)
			if(channel->ssrc == id) return channel;
	}
	return nullptr;
}

std::deque<std::shared_ptr<MediaChannel>> MediaStream::list_channels(direction::value direction) {
	std::deque<std::shared_ptr<MediaChannel>> result;
	if((direction & direction::outgoing) > 0) {
		for(const auto& channel : this->local_channels)
			result.push_back(channel);
	}
	if((direction & direction::incoming) > 0) {
		for(const auto& channel : this->remote_channels)
			result.push_back(channel);
	}
	return result;
}

std::shared_ptr<HeaderExtension> MediaStream::find_extension_by_id(uint8_t id, direction::value direction) {
	if((direction & direction::outgoing) > 0) {
		for(const auto& ext : this->local_extensions)
			if(ext->id == id) return ext;
	}
	if((direction & direction::incoming) > 0) {
		for(const auto& ext : this->remote_extensions)
			if(ext->id == id) return ext;
	}
	return nullptr;
}

std::deque<std::shared_ptr<HeaderExtension>> MediaStream::list_extensions(direction::value direction) {
	std::deque<std::shared_ptr<HeaderExtension>> result;
	if((direction & direction::outgoing) > 0) {
		for(const auto& ext : this->local_extensions)
			result.push_back(ext);
	}
	if((direction & direction::incoming) > 0) {
		for(const auto& ext : this->remote_extensions)
			result.push_back(ext);
	}
	return result;
}

static bool srtp_initialized = false;
MediaStream::MediaStream(rtc::PeerConnection *owner, rtc::NiceStreamId id, std::shared_ptr<rtc::MediaStream::Configuration> config) : Channel(owner, id), config(std::move(config)) {
	memset(&this->remote_policy, 0, sizeof(remote_policy));
	memset(&this->local_policy, 0, sizeof(local_policy));
	if(!srtp_initialized) {
		if(srtp_init() != srtp_err_status_ok) {
			//FIXME error handling
		}
		srtp_initialized = true;
	}
}
MediaStream::~MediaStream() {
	string error;
	this->reset(error);
}

bool MediaStream::initialize(std::string &error) {
	return true;
}

void MediaStream::on_dtls_initialized(const std::shared_ptr<DTLSHandler> &handle) {
	LOG_DEBUG(this->config->logger, "RTPStream::dtls", "Initialized!");

	const auto pipe = handle->dtls_pipe();
	auto profile = SSL_get_selected_srtp_profile(pipe->ssl_handle());
	if(!profile) {
		LOG_ERROR(this->config->logger, "RTPStream::dtls", "Missing remote's srtp profile!");
		return;
	}
	LOG_DEBUG(this->config->logger, "RTPStream::srtp", "Got profile @%p. Name: %s Id: %i", profile, profile->name, profile->id);

	int key_length = 0, salt_length = 0, master_length = 0;
	switch(profile->id) {
		case SRTP_AES128_CM_SHA1_80:
		case SRTP_AES128_CM_SHA1_32:
			key_length = SRTP_MASTER_KEY_LENGTH;
			salt_length = SRTP_MASTER_SALT_LENGTH;
			master_length = SRTP_MASTER_LENGTH;
			break;
#ifdef HAVE_SRTP_AESGCM
		case SRTP_AEAD_AES_256_GCM:
            key_length = SRTP_AESGCM256_MASTER_KEY_LENGTH;
            salt_length = SRTP_AESGCM256_MASTER_SALT_LENGTH;
            master_length = SRTP_AESGCM256_MASTER_LENGTH;
            break;
        case SRTP_AEAD_AES_128_GCM:
            key_length = SRTP_AESGCM128_MASTER_KEY_LENGTH;
            salt_length = SRTP_AESGCM128_MASTER_SALT_LENGTH;
            master_length = SRTP_AESGCM128_MASTER_LENGTH;
            break;
#endif
		default:
			/* Will never happen? */
			LOG_DEBUG(this->config->logger, "RTPStream::srtp", "Unsupported profile %i (%s)", profile->id, profile->id);
			break;
	}
	LOG_DEBUG(this->config->logger, "RTPStream::srtp", "Key/Salt/Master: %d/%d/%d", master_length, key_length, salt_length);


	/* Complete with SRTP setup */
	unsigned char material[SRTP_MAX_MASTER_LENGTH * 2];
    assert(master_length <= SRTP_MAX_MASTER_LENGTH); /* requirement for the array above and all following arrays */

	memset(material, 0x00, master_length * 2);
	unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
	/* Export keying material for SRTP */
	if(!SSL_export_keying_material(pipe->ssl_handle(), material, master_length * 2, "EXTRACTOR-dtls_srtp", 19, nullptr, 0, 0)) {
		LOG_ERROR(this->config->logger, "RTPStream::srtp", "Failed to setup SRTP key materinal!");
		return; //FIXME error handling
	}
	/* Key derivation (http://tools.ietf.org/html/rfc5764#section-4.2) */
	if(pipe->options()->type == pipes::TLS::CLIENT) {
		local_key = material;
		remote_key = local_key + key_length;
		local_salt = remote_key + key_length;
		remote_salt = local_salt + salt_length;
	} else {
		remote_key = material;
		local_key = remote_key + key_length;
		remote_salt = local_key + key_length;
		local_salt = remote_salt + salt_length;
	}

	u_char remote_policy_key[SRTP_MAX_MASTER_LENGTH];
	u_char local_policy_key[SRTP_MAX_MASTER_LENGTH];
	{
		/* Remote (inbound) */
		switch(profile->id) {
			case SRTP_AES128_CM_SHA1_80:
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(remote_policy.rtp));
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(remote_policy.rtcp));
				break;
			case SRTP_AES128_CM_SHA1_32:
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(remote_policy.rtp));
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(remote_policy.rtcp));
				break;
#ifdef HAVE_SRTP_AESGCM
			case SRTP_AEAD_AES_256_GCM:
                srtp_crypto_policy_set_aes_gcm_256_16_auth(&(this->remote_policy.rtp));
                srtp_crypto_policy_set_aes_gcm_256_16_auth(&(this->remote_policy.rtcp));
                break;
            case SRTP_AEAD_AES_128_GCM:
                srtp_crypto_policy_set_aes_gcm_128_16_auth(&(this->remote_policy.rtp));
                srtp_crypto_policy_set_aes_gcm_128_16_auth(&(this->remote_policy.rtcp));
                break;
#endif
			default:
				break;
		}

		this->remote_policy.ssrc.type = ssrc_any_inbound;
		this->remote_policy.key = (u_char*) &remote_policy_key;
		memcpy(this->remote_policy.key, remote_key, key_length);
		memcpy(this->remote_policy.key + key_length, remote_salt, salt_length);
#if HAS_DTLS_WINDOW_SIZE
		this->remote_policy.window_size = 128;
        this->remote_policy.allow_repeat_tx = 0;
#endif
		this->remote_policy.next = nullptr;
	}

	{
		/* Local (outbound) */
		switch(profile->id) {
			case SRTP_AES128_CM_SHA1_80:
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(local_policy.rtp));
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(local_policy.rtcp));
				break;
			case SRTP_AES128_CM_SHA1_32:
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(local_policy.rtp));
				srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(local_policy.rtcp));
				break;
#ifdef HAVE_SRTP_AESGCM
			case SRTP_AEAD_AES_256_GCM:
                srtp_crypto_policy_set_aes_gcm_256_16_auth(&(this->local_policy.rtp));
                srtp_crypto_policy_set_aes_gcm_256_16_auth(&(this->local_policy.rtcp));
                break;
            case SRTP_AEAD_AES_128_GCM:
                srtp_crypto_policy_set_aes_gcm_128_16_auth(&(this->local_policy.rtp));
                srtp_crypto_policy_set_aes_gcm_128_16_auth(&(this->local_policy.rtcp));
                break;
#endif
			default:
				break;
		}
		this->local_policy.ssrc.type = ssrc_any_outbound;
		this->local_policy.key = (u_char*) &local_policy_key;
		memcpy(this->local_policy.key, local_key, key_length);
		memcpy(this->local_policy.key + key_length, local_salt, salt_length);
#if HAS_DTLS_WINDOW_SIZE
		this->local_policy.window_size = 128;
		this->local_policy.allow_repeat_tx = 0;
#endif
		this->local_policy.next = nullptr;
	}

	{
		/* Create SRTP sessions */
		srtp_err_status_t res = srtp_create(&(this->srtp_in), &(this->remote_policy));
		if(res != srtp_err_status_ok) {
			LOG_ERROR(this->config->logger, "RTPStream::srtp", "Failed to create srtp session (remote)! Code %i", res);
			return; //FIXME error handling
		}
		this->srtp_in_ready = true;

		res = srtp_create(&(this->srtp_out), &(this->local_policy));
		if(res != srtp_err_status_ok) {

			LOG_ERROR(this->config->logger, "RTPStream::srtp", "Failed to create srtp session (local)! Code %i", res);
			return; //FIXME error handling
		}
		this->srtp_out_ready = true;
	}
}

bool MediaStream::apply_sdp(const json_guard& sdp, const json_guard& media_entry) {
	{
		TEST_AV_TYPE(media_entry, "mid", is_string, return false, "RTPStream::apply_sdp", "Entry contains invalid/missing mid");
		this->mid = media_entry["mid"];
		LOG_DEBUG(this->config->logger, "RTPStream::apply_sdp", "Got mid type %s", this->mid.c_str());
	}

    {
        std::cout << nlohmann::to_string(sdp) << "\n";
    }

	if(media_entry.count("ssrcs") > 0) { //Parse remote streams
		const json_guard& ssrcs = media_entry["ssrcs"];
		if(!ssrcs.is_array()) return false;

		for (const auto &ssrc : ssrcs) {
			TEST_AV_TYPE(ssrc, "attribute", is_string, continue, "RTPStream::apply_sdp", "SSRC contains invalid/missing attribute");
			TEST_AV_TYPE(ssrc, "id", is_number, continue, "RTPStream::apply_sdp", "SSRC contains invalid/missing id");

			string attribute = ssrc["attribute"];
			uint32_t ssrc_id = ssrc["id"];
			shared_ptr<MediaChannel> channel;
			{
				for(const auto& ch : this->remote_channels) {
					if(ch->ssrc == ssrc_id) {
						channel = ch;
						break;
					}
				}

				if(!channel) {
					channel = make_shared<MediaChannel>();
					channel->ssrc = ssrc_id;
					channel->local = false;
					this->remote_channels.push_back(channel);
				}
			}

			if(attribute == "mslabel") {
				TEST_AV_TYPE(ssrc, "value", is_string, continue, "RTPStream::apply_sdp", "SSRC contains invalid value");
                channel->stream_label = ssrc["value"];
			} else if(attribute == "label") {
				TEST_AV_TYPE(ssrc, "value", is_string, continue, "RTPStream::apply_sdp", "SSRC contains invalid value");
                channel->track_label = ssrc["value"];
			} else if(attribute == "msid") {
			    /* test association */
			}
		}
		LOG_DEBUG(this->config->logger, "RTPStream::apply_sdp", "Got %u remote channels", this->remote_channels.size());
	}

	{
		size_t supported = 0;
		if(media_entry.count("rtp") > 0) { //codecs
			const json_guard& rtp = media_entry["rtp"];
			if(!rtp.is_array()) return false;

			for (const auto &index : rtp) {
				auto map = codec::create(index);
				if(!map) {
					//TODO log error
					continue;
				}
				if(map->local_accepted()) supported += 1;
				this->offered_codecs.push_back(map);
			}
		}
		if(media_entry.count("fmtp") > 0) { /* codec specific parameters */
			const json_guard& rtp = media_entry["fmtp"];
			if(!rtp.is_array()) return false;

			for (const auto &parameter : rtp) {
				TEST_AV_TYPE(parameter, "payload", is_number, continue, "RTPStream::apply_sdp", "Codec parameters contains invalid/missing payload");
				TEST_AV_TYPE(parameter, "config", is_string, continue, "RTPStream::apply_sdp", "Codec parameters contains invalid/missing condif");

				auto codec = this->find_codec_by_id(parameter["payload"]);
				if(!codec) return false;

				codec->parameters.push_back(parameter["config"]);
			}

		}
		LOG_DEBUG(this->config->logger, "RTPStream::apply_sdp", "Got %u remote offered codecs. (%u locally supported)", this->offered_codecs.size(), supported);
	}

	if(media_entry.count("ext") > 0) { //Parse extensions
		this->remote_extensions.reserve(media_entry.count("ext"));

		const json_guard& exts = media_entry["ext"];
		if(!exts.is_array()) return false;

		for (const auto &ext : exts) {
			auto extension = make_shared<HeaderExtension>();
			TEST_AV_TYPE(ext, "value", is_number, continue, "RTPStream::apply_sdp", "Extension contains invalid/missing value");
			TEST_AV_TYPE(ext, "uri", is_string, continue, "RTPStream::apply_sdp", "Extension contains invalid/missing uri");

			extension->local = false;
			extension->id = ext["value"];
			extension->name = ext["uri"];
			extension->config = "";
			extension->direction = "";
			if(ext.count("config") > 0 && ext["config"].is_string()) {
				extension->config = ext["config"];
			}
			if(ext.count("direction") > 0 && ext["direction"].is_string()) {
				extension->config = ext["direction"];
			}

			this->remote_extensions.push_back(std::move(extension));
		}
	}
	return true;
}

string MediaStream::generate_sdp() {
	ostringstream sdp;

	string ids;
	for(const auto& codec : this->offered_codecs) {
		if(!codec->local_accepted()) continue;
		ids += " " + to_string((uint32_t) codec->id);
	}
	sdp << "m=" << this->sdp_media_type() << " 9 UDP/TLS/RTP/SAVPF " << (ids.empty() ? "" : ids.substr(1)) << "\r\n";
	sdp << "c=IN IP4 0.0.0.0\r\n";
	{
		sdp << "a=";
		if(this->remote_channels.empty())
			sdp << "sendonly";
		else if(this->local_channels.empty())
			sdp << "recvonly";
		else
			sdp << "sendrecv";
		sdp << "\r\n";
	}
	sdp << "a=mid:" << this->mid << "\r\n";
	sdp << "a=rtcp-mux\r\n";

	for(const auto& extension : this->local_extensions) {
		sdp << "a=extmap:" << (int) extension->id;
		if(!extension->direction.empty())
			sdp << "/" << extension->direction;
		sdp << " " << extension->name;
		if(!extension->config.empty())
			sdp << " " << extension->config;
		sdp << "\r\n";
	}

	for(const auto& codec : this->offered_codecs) {
		if(!codec->local_accepted()) continue;
		codec->write_sdp(sdp);
	}

	for(const auto& channel : this->local_channels) {
		sdp << "a=ssrc:" << channel->ssrc << " cname:" << channel->id << "\r\n";
		if(channel->track_label.has_value()) {
		    sdp << "a=ssrc:" << channel->ssrc << " label:" << *channel->track_label << "\r\n";

		    if(channel->stream_label.has_value()) {
                sdp << "a=ssrc:" << channel->ssrc << " mslabel:" << *channel->stream_label << "\r\n";
                sdp << "a=ssrc:" << channel->ssrc << " msid:" << *channel->track_label << " " << *channel->stream_label << "\r\n";
		    } else {
                sdp << "a=ssrc:" << channel->ssrc << " msid:" << *channel->track_label << "\r\n";
		    }
		}
	}
	return sdp.str();
}

bool MediaStream::reset(std::string &string) {
	this->srtp_out_ready = false;
	if(this->srtp_out) {
		if(srtp_dealloc(this->srtp_out) != srtp_err_status_ok); //TODO error handling?
		this->srtp_out = nullptr;
	}

	this->srtp_in_ready = false;
	if(this->srtp_in) {
		if(srtp_dealloc(this->srtp_in) != srtp_err_status_ok); //TODO error handling?
		this->srtp_in = nullptr;
	}
	return true;
}

bool MediaStream::process_incoming_rtp_data(RTPPacket &packet) {
    auto channel = this->find_track_by_id(htonl(packet.buffer.data_ptr<protocol::rtp_header>()->ssrc),
                                          direction::incoming);
    if(!channel)
        return false;

    if(packet.crypt_state == CryptState::ENCRYPTED) {
        if(!this->srtp_in_ready) {
            LOG_ERROR(this->config->logger, "RTPStream::process_incoming_rtp_data", "Got too early packet!");
            return true;
        }

        auto buflen = packet.buffer.length();
        srtp_err_status_t res = srtp_unprotect(this->srtp_in, (void*) packet.buffer.data_ptr(), (int*) &buflen);
        if(res != srtp_err_status_ok) {
            if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
                /* Only print the error if it's not a 'replay fail' or 'replay old' (which is probably just the result of us NACKing a packet) */
                packet.crypt_state = CryptState::DECRYPT_FAILED;
                LOG_ERROR(this->config->logger, "RTPStream::process_incoming_rtp_data", "Failed to unprotect  RTP packet. Error %i (len=%i)", buflen, packet.buffer.length());
                return true;
            }
        }
        packet.buffer = packet.buffer.view(0, buflen);
        packet.crypt_state = CryptState::DECRYPTED_VERIFIED;
    } else if(packet.crypt_state != CryptState::DECRYPTED_VERIFIED) {
        return true;
    }
    this->process_rtp_data(channel, packet.buffer);
    return true;
}

bool MediaStream::process_incoming_rtcp_data(RTCPPacket &packet) {
    auto channel = this->find_track_by_id(htonl(packet.buffer.data_ptr<protocol::rtcp_header>()->ssrc),
                                          direction::incoming);
    if(!channel)
        return false;

    if(packet.crypt_state == CryptState::ENCRYPTED) {
        if(!this->srtp_in_ready) {
            LOG_ERROR(this->config->logger, "RTPStream::process_incoming_rtcp_data", "Got too early packet!");
            return true;
        }

        auto buflen = packet.buffer.length();
        srtp_err_status_t res = srtp_unprotect_rtcp(this->srtp_in, (void*) packet.buffer.data_ptr(), (int*) &buflen);
        if(res != srtp_err_status_ok) {
            if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
                /* Only print the error if it's not a 'replay fail' or 'replay old' (which is probably just the result of us NACKing a packet) */
                packet.crypt_state = CryptState::DECRYPT_FAILED;
                LOG_ERROR(this->config->logger, "RTPStream::process_incoming_rtcp_data", "Failed to unprotect  RTCP packet. Error %i (len=%i --> %i)", buflen, packet.buffer.length(), buflen);
                return true;
            }
        }
        packet.buffer = packet.buffer.view(0, buflen);
        packet.crypt_state = CryptState::DECRYPTED_VERIFIED;
    } else if(packet.crypt_state != CryptState::DECRYPTED_VERIFIED) {
        return true;
    }
    this->process_rtcp_data(channel, packet.buffer);
    return true;
}

bool MediaStream::process_incoming_dtls_data(const pipes::buffer_view &) {
    return false;
}

//#define ENABLE_PROTOCOL_LOGGING
void MediaStream::process_rtp_data(const shared_ptr<MediaChannel>& channel, const pipes::buffer_view&in) {
    auto header = (protocol::rtp_header*) in.data_ptr();

#ifdef ENABLE_PROTOCOL_LOGGING
	LOG_VERBOSE(this->config->logger, "MediaStream::process_rtp_data", "incoming %i --> %i decrypted bytes. Type %i Version %i SSRC: %u => %i Seq: %u Pad: %u Ext: %u Ver: %u Mark: %u Count: %u", in.length(), buflen, (unsigned int) header->type, (unsigned int) header->version, be32toh(header->ssrc), (unsigned int) header->csrccount, ntohs(header->seq_number), (int) header->padding, (int) header->extension, (int) header->version, (int) header->markerbit, (int) header->csrccount);
	if(header->extension) {
		auto ext = (protocol::rtp_header_extension*) (in.data() + 12);
		LOG_VERBOSE(this->config->logger, "XX", "Extenstion bytes (%x %u) %x %x %x %x", be16toh(ext->type), be16toh(ext->length), ext->data[0], ext->data[1], ext->data[2], ext->data[3]);
	}
#endif

	auto payload_offset = protocol::rtp_payload_offset(in);
	if(payload_offset < 0 || (size_t) payload_offset >= in.length()) {
	    //TODo: Evaluate if it might not only contain header extensions and if this would be valid according to the RFC XXXX
	    LOG_ERROR(this->config->logger, "RTPStream::process_rtp_data", "Received packet which contains no payload data. Dropping packet.");
	    return;
	}

	if(!channel->codec) {
		for(const auto& codec : this->offered_codecs) {
			if(codec->id == header->type) {
				if(codec->local_accepted()) {
					channel->codec = codec; //TODO fire event?
					break;
				}
			}
		}
		if(!channel->codec) {
			LOG_ERROR(this->config->logger, "RTPStream::process_rtp_data", "Channel %u (%s) does not contains a codec which is locally supported!", be32toh(header->ssrc), channel->id.c_str());
			return;
		}
	}

	if(channel->codec->id != header->type) {
		LOG_ERROR(this->config->logger, "RTPStream::process_rtp_data", "Received type %u for channel %u (%s) does not match predefined type %u (%s)!", (int) header->type, be32toh(header->ssrc), channel->id.c_str(), (int) channel->codec->id, channel->codec->codec.c_str());
		return;
	}

	channel->timestamp_last_receive = ntohl(header->timestamp);
	if(this->incoming_data_handler)
		this->incoming_data_handler(channel, in, payload_offset);
}

bool MediaStream::send_rtp_data(const shared_ptr<MediaChannel> &stream, const pipes::buffer_view &extensions_and_payload, uint32_t timestamp, bool flag_extension, int marker_bit) {
	static_assert(protocol::rtp_header_base_size == 12, "Invalid structure size");
	static_assert(protocol::rtp_header_extension_size == 4, "Invalid structure size");
	if(!this->srtp_out_ready) {
		LOG_ERROR(this->config->logger, "RTPStream::send_rtp_data", "Srtp not ready yet!");
		return false;
	}
	if(!stream || !stream->codec) {
		LOG_ERROR(this->config->logger, "RTPStream::send_rtp_data", "Stream hasn't a codec yet or is null!");
		return false;
	}

	auto allocated = protocol::rtp_header_base_size + extensions_and_payload.length() + SRTP_MAX_TRAILER_LEN;
	allocated += allocated % 4; //Align 32 bits

	pipes::buffer buffer(allocated);
	auto header = (protocol::rtp_header*) buffer.data_ptr();

	header->type = stream->codec->id;
	header->ssrc = htobe32(stream->ssrc);
	header->csrccount = 0;
	header->version = 2;
	header->padding = 0;
	header->extension = (uint16_t) (flag_extension ? 1 : 0);
	header->markerbit = (uint16_t) (marker_bit == -1 ? stream->index_packet_send == 0 : marker_bit != 0);
	header->timestamp = htonl(timestamp);
	header->seq_number = htons(stream->index_packet_send);

	stream->index_packet_send += 1;
    stream->timestamp_last_send = timestamp;

	int offset_payload = protocol::rtp_header_base_size;
	memcpy((void*) &buffer[offset_payload], extensions_and_payload.data_ptr(), extensions_and_payload.length());

	auto org_buflen = offset_payload + extensions_and_payload.length();
	auto buflen = org_buflen; //SRTP_MAX_TRAILER_LEN
	srtp_err_status_t res = srtp_protect(this->srtp_out, (void*) buffer.data_ptr(), (int*) &buflen);
	if(res != srtp_err_status_ok) {
		if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
			LOG_ERROR(this->config->logger, "RTPStream::process_rtp_data", "Failed to protect srtp packet. Error: %i (len=%i --> %i)", res, buffer.length(), buflen);
			return false;
		}
	}
	assert(buffer.length() >= buflen);
#ifdef ENABLE_PROTOCOL_LOGGING
	LOG_ERROR(this->config->logger, "MediaStream::process_srtp_data", "Protect succeeed %i (len=%i --> %i | len_org=%i)", res, buffer.length(), buflen, org_buflen);
#endif

	this->send_data(buffer.view(0, buflen), false);
	return true;
}

#define DEFINE_GETTER_SETTER(name, type) \
[[nodiscard]] inline type name() const { return this->_ ##name; } \
inline void name(type value) { this->_ ##name = value; }

#define DEFINE_GETTER_SETTER_VAR(name, type, var) \
[[nodiscard]] inline type name() const { return this->var; } \
inline void name(type value) { this->var = value; }

#define PARSE_ERROR(message) \
do {\
    error = (message); \
    return false; \
} while(0)

#define WRITE_ERROR(message) \
do {\
    error = (message); \
    return -1; \
} while(0)

struct RTCPHeader {
public:
    static constexpr size_t header_byte_size = 4;

    bool parse(const uint8_t* buffer, size_t max_bytes, std::string& error) {
        if(max_bytes < header_byte_size) PARSE_ERROR("too little data");
        if((buffer[0] >> 6U) != 2) PARSE_ERROR("invalid version");

        this->_padding = (buffer[0] & 0x20) != 0;
        this->_count_or_format = buffer[0] & 0x1FU;
        this->_packet_type = (protocol::rtcp_type) buffer[1];
        this->_payload_byte_size = ntohs(*(uint16_t*) &buffer[2]) * 4;
    }

    ssize_t write(uint8_t* buffer, size_t max_bytes, std::string& error) {
        if(max_bytes < header_byte_size) WRITE_ERROR("too little data");
        buffer[0] = (2U << 6U) | ((this->_padding ? 1U : 0U) << 5U) | (this->_count_or_format & 0x1FU);
        buffer[1] = this->_packet_type;
        *(uint16_t*) &buffer[2] = htons((this->_payload_byte_size + 3) / 4);
        return header_byte_size;
    }

    DEFINE_GETTER_SETTER(packet_type, protocol::rtcp_type);
    DEFINE_GETTER_SETTER(padding, bool);
    DEFINE_GETTER_SETTER(payload_byte_size, uint32_t);

    DEFINE_GETTER_SETTER_VAR(count, uint8_t, _count_or_format);
    DEFINE_GETTER_SETTER_VAR(format, uint8_t, _count_or_format);
private:
    bool _padding{false};
    protocol::rtcp_type _packet_type{0};
    uint8_t _count_or_format{0};
    uint32_t _payload_byte_size{0};
};

bool MediaStream::send_rtcp_data(const std::shared_ptr <MediaChannel> &channel, const pipes::buffer_view &payload, protocol::rtcp_type pt, int rc) {
    if(!this->srtp_out_ready) {
        LOG_ERROR(this->config->logger, "RTPStream::send_rtcp_data", "Srtp not ready yet!");
        return false;
    }
    std::string error{};

    pipes::buffer buffer(protocol::rtcp::rtcp_header::size + payload.length() + SRTP_MAX_TRAILER_LEN + 4);

    size_t buffer_offset{0};
    {
        RTCPHeader header{};
        header.format(rc);
        header.packet_type(pt);
        header.payload_byte_size(payload.length()); //Plus 8 for the header
        if(auto written = header.write(buffer.data_ptr<uint8_t>() + buffer_offset, buffer.length() - buffer_offset, error); written < 0) {
            LOG_ERROR(this->config->logger, "RTPStream::send_rtcp_data", "Failed to write header: %s", error.c_str());
            return false;
        } else {
            buffer_offset += written;
        }
    }
    memcpy(buffer.data_ptr<uint8_t>() + buffer_offset, payload.data_ptr(), payload.length());
    buffer_offset += payload.length();

    auto buflen = buffer_offset;
    const auto data = buffer.data_ptr();
    srtp_err_status_t res = srtp_protect_rtcp(this->srtp_out, (void*) buffer.data_ptr(), (int*) &buflen);
    if(res != srtp_err_status_ok) {
        if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
            LOG_ERROR(this->config->logger, "RTPStream::process_rtp_data", "Failed to protect srtcp packet. Error: %i (len=%i --> %i)", res, buffer.length(), buflen);
            return false;
        }
    }
    assert(buffer.length() >= buflen);

    this->send_data(buffer.view(0, buflen), false);
    return true;
}

void MediaStream::process_rtcp_data(const shared_ptr<MediaChannel>& channel, const pipes::buffer_view& in) {
	auto header = (protocol::rtcp_header*) in.data_ptr();

	if(header->type == 200) { /* sender report */
		//https://www4.cs.fau.de/Projects/JRTP/pmt/node83.html

		if(ntohs(header->length) < 6 || in.length() < protocol::rtcp::sender_report::size + protocol::rtcp::rtcp_header::size) {
			LOG_ERROR(this->config->logger, "RTPStream::process_rtcp_data", "Received invalid sender report for stream %ui (Length: %i (shall be equal or greater 6))", (int) header->ssrc, (int) ntohs(header->length));
			return;
		}
		//TODO validate stream

		protocol::rtcp::sender_report report{(uint32_t*) in.data_ptr(), in.length()};
		LOG_DEBUG(this->config->logger,
				"RTPStream::process_rtcp_data", "Received sender report for stream %" PRIu32 ": {network_timestamp: %" PRIu64 " rtp_timestamp: %" PRIu32 " packets: %" PRIu32 "; bytes: %" PRIu32 "}",
				be32toh(header->ssrc),
				report.network_timestamp(),
				report.rtp_timestamp(),
				report.packet_count(),
				report.octet_count()
		);


		LOG_DEBUG(this->config->logger, "RTPStream::process_rtcp_data", "Received %" PRIu32 " receiver reports within sender report", report.receiver_report_blocks().size());
		for(auto& block : report.receiver_report_blocks()) {
			LOG_DEBUG(this->config->logger,
			          "RTPStream::process_rtcp_data", "  ssrc %" PRIu32 ": {lost.{fraction: %" PRIu8 " packets: %" PRIu32 "} highest_sequence_number: %" PRIu32 " interarrival_jitter: %" PRIu32 " last_sender_report: %" PRIu32 " delay_last_sender_report: %" PRIu32 " }",
			          block.ssrc(),
			          block.fraction_lost(),
			          block.packets_lost(),
			          block.highest_sequence_number(),
			          block.interarrival_jitter(),
			          block.delay_last_sender_report(),
			          block.delay_last_sender_report()
			);
			(void) block;
		}
		return;
	} else if(header->type == 201) { /* receiver report */
		//https://www4.cs.fau.de/Projects/JRTP/pmt/node84.html

		protocol::rtcp::receiver_report report{(uint32_t*) in.data_ptr(), in.length()};
		LOG_DEBUG(this->config->logger, "RTPStream::process_rtcp_data", "Received %" PRIu32 " receiver reports. (Total length: %" PRIu32 ")", report.report_count(), report.length());
		for(auto& block : report.report_blocks()) {
			LOG_DEBUG(this->config->logger,
					"RTPStream::process_rtcp_data", "  ssrc %" PRIu32 ": {lost.{fraction: %" PRIu8 " packets: %" PRIu32 "} highest_sequence_number: %" PRIu32 " interarrival_jitter: %" PRIu32 " last_sender_report: %" PRIu32 " delay_last_sender_report: %" PRIu32 " }",
					block.ssrc(),
					block.fraction_lost(),
					block.packets_lost(),
					block.highest_sequence_number(),
					block.interarrival_jitter(),
					block.delay_last_sender_report(),
					block.delay_last_sender_report()
			);
			(void) block;
		}
	} else {
		LOG_DEBUG(this->config->logger, "RTPStream::process_rtcp_data", "Got RTCP packet of type %i and length %i (buffer: %i)", (int) header->type, (int) ntohs(header->length), in.length() - sizeof(protocol::rtcp_header));
	}
}
