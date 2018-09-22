#include "json.hpp"
#include "include/misc/endianness.h"
#include "include/rtc/PeerConnection.h"
#include "include/rtc/AudioStream.h"
#include "include/tls.h"
#include "include/sctp.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"
#include <srtp/srtp.h>
#include <openssl/srtp.h>

using namespace std;
using namespace std::chrono;
using namespace rtc;
using namespace rtc::codec;

#define srtp_err_status_t err_status_t
#define srtp_err_status_ok err_status_ok
#define srtp_err_status_replay_fail err_status_replay_fail
#define srtp_err_status_replay_old err_status_replay_old

/* SRTP stuff (http://tools.ietf.org/html/rfc3711) */
/*
cipher_key_length:  128
cipher_salt_length:  112
*/
#define SRTP_MASTER_KEY_LENGTH	(128 / 8) // => 16 bytes
#define SRTP_MASTER_SALT_LENGTH	(112 / 8) // => 12 bytes

#define SRTP_MASTER_LENGTH (SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH)
/*
 * #define SSL3_MASTER_SECRET_SIZE 48
#define SSL3_RANDOM_SIZE 32
 */
/* AES-GCM stuff (http://tools.ietf.org/html/rfc7714) */
#define SRTP_AESGCM128_MASTER_KEY_LENGTH	16
#define SRTP_AESGCM128_MASTER_SALT_LENGTH	12
#define SRTP_AESGCM128_MASTER_LENGTH (SRTP_AESGCM128_MASTER_KEY_LENGTH + SRTP_AESGCM128_MASTER_SALT_LENGTH)
#define SRTP_AESGCM256_MASTER_KEY_LENGTH	32
#define SRTP_AESGCM256_MASTER_SALT_LENGTH	12
#define SRTP_AESGCM256_MASTER_LENGTH (SRTP_AESGCM256_MASTER_KEY_LENGTH + SRTP_AESGCM256_MASTER_SALT_LENGTH)
#define srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32 crypto_policy_set_aes_cm_128_hmac_sha1_32
#define srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80 crypto_policy_set_aes_cm_128_hmac_sha1_80
#define srtp_crypto_policy_set_aes_gcm_256_16_auth crypto_policy_set_aes_gcm_256_16_auth
#define srtp_crypto_policy_set_aes_gcm_128_16_auth crypto_policy_set_aes_gcm_128_16_auth

std::shared_ptr<TypedAudio> codec::create(const nlohmann::json& sdp) {
	std::shared_ptr<TypedAudio> result;
	if(sdp["codec"] == "opus") {
		auto _result = make_shared<OpusAudio>();
		_result->type = TypedAudio::OPUS;
		_result->sample_rate = sdp["rate"];
		_result->encoding = sdp["encoding"];
		result = std::move(_result);
	}
	//TODO implement more

	if(!result) result = make_shared<UnknownAudio>();

	if(!result->type) result->type = TypedAudio::UNKNOWN;
	result->id = sdp["payload"];
	result->codec = sdp["codec"];

	return result;
}

bool OpusAudio::write_sdp(std::ostringstream &sdp) {
	sdp << "a=rtpmap:" << (uint32_t) this->id << " opus/" << this->sample_rate << "/2\r\n"; //We want opus music 48kHz
	sdp << "a=fmtp:" << (uint32_t) this->id << " maxplaybackrate=16000; stereo=0; sprop-stereo=0; useinbandfec=1\r\n"; //Some opus specs
	return true;
}

bool OpusAudio::local_supported() const { return true; }

bool UnknownAudio::write_sdp(std::ostringstream &) { return true; }
bool UnknownAudio::local_supported() const { return false; }

std::deque<std::shared_ptr<codec::TypedAudio>> AudioStream::find_codec_by_name(const std::string &name) {
	deque<shared_ptr<codec::TypedAudio>> result;

	for(const auto& codec : this->offered_codecs)
		if(codec->codec == name) result.push_back(codec);

	return result;
}

void AudioStream::register_local_channel(const std::string &stream_id, const std::string &track_id, const shared_ptr<rtc::codec::TypedAudio> &type) {
	auto channel = make_shared<AudioChannel>();
	channel->stream_id = stream_id;
	channel->track_id = track_id;
	channel->codec = type;
	channel->local = true;

	for(const auto& ch : this->list_channels(0x01))
		if(ch->track_id == track_id) throw std::invalid_argument("Track with id \"" + track_id + "\" already exists!");

	while(!channel->ssrc || this->find_channel_by_id(channel->ssrc)) channel->ssrc = rand();

	this->local_channels.push_back(channel);
}

std::shared_ptr<AudioChannel> AudioStream::find_channel_by_id(uint32_t id, uint8_t direction) {
	if(direction & 0x01) {
		for(const auto& channel : this->local_channels)
			if(channel->ssrc == id) return channel;
	}
	if(direction & 0x02) {
		for(const auto& channel : this->remote_channels)
			if(channel->ssrc == id) return channel;
	}
	return nullptr;
}

std::deque<std::shared_ptr<AudioChannel>> AudioStream::list_channels(uint8_t direction) {
	std::deque<std::shared_ptr<AudioChannel>> result;
	if(direction & 0x01) {
		for(const auto& channel : this->local_channels)
			result.push_back(channel);
	}
	if(direction & 0x02) {
		for(const auto& channel : this->remote_channels)
			result.push_back(channel);
	}
	return result;
}

const std::vector<std::shared_ptr<HeaderExtension>>& AudioStream::list_offered_extensions() {
	return this->offered_extensions;
}

static bool srtp_initialized = false;
AudioStream::AudioStream(rtc::PeerConnection *owner, rtc::StreamId id, const std::shared_ptr<rtc::AudioStream::Configuration> &config) : Stream(owner, id), config(config) {
	memset(&this->remote_policy, 0, sizeof(remote_policy));
	memset(&this->local_policy, 0, sizeof(local_policy));
	if(!srtp_initialized) {
		if(srtp_init() != srtp_err_status_ok) {
			//FIXME error handling
		}
		srtp_initialized = true;
	}
}
AudioStream::~AudioStream() {
	string error;
	this->reset(error);
}

//TODO Allow AES
bool AudioStream::initialize(std::string &error) {
	{
		this->dtls = make_unique<pipes::TLS>();
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_IN, true);
		this->dtls->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
		this->dtls->logger(this->config->logger);

		this->dtls->callback_data([&](const string& data) {
			LOG_VERBOSE(this->config->logger, "AudioStream::dtls", "Got incoming bytes (%i). This should never happen!", data.length());
		});
		this->dtls->callback_write([&](const string& data) {
			LOG_VERBOSE(this->config->logger, "AudioStream::dtls", "outgoing %i bytes", data.length());
			this->send_data(data);
		});
		this->dtls->callback_error([&](int code, const std::string& error) {
			LOG_ERROR(this->config->logger, "AudioStream::dtls", "Got error (%i): %s", code, error.c_str());
		});
		this->dtls->callback_initialized = [&](){
			this->dtls_initialized = true;
			LOG_DEBUG(this->config->logger, "AudioStream::dtls", "Initialized!");

			{
				/* Check the remote fingerprint */

				X509 *rcert = SSL_get_peer_certificate(this->dtls->ssl_handle());
				if(!rcert) {
					LOG_ERROR(this->config->logger, "AudioStream::srtp", "Failed to verify remote certificate (certificate missing)");
					return;
				} else {
					unsigned int rsize;
					unsigned char rfingerprint[EVP_MAX_MD_SIZE];
					char remote_fingerprint[160];
					char *rfp = (char *) &remote_fingerprint;
					if (false) {
						X509_digest(rcert, EVP_sha1(), (unsigned char *) rfingerprint, &rsize);
					} else {
						X509_digest(rcert, EVP_sha256(), (unsigned char *) rfingerprint, &rsize);
					}
					X509_free(rcert);
					rcert = NULL;
					unsigned int i = 0;
					for (i = 0; i < rsize; i++) {
						g_snprintf(rfp, 4, "%.2X:", rfingerprint[i]);
						rfp += 3;
					}
					*(rfp - 1) = 0;
					LOG_VERBOSE(this->config->logger, "AudioStream::srtp", "Generated remote fingerprint: %s", remote_fingerprint);
					//TODO test fingerprint!
				}
			}

			//TODO signature test etc?
			auto profile = SSL_get_selected_srtp_profile(this->dtls->ssl_handle());
			LOG_DEBUG(this->config->logger, "AudioStream::srtp", "Got profile @%p. Name: %s Id: %i", profile, profile->name, profile->id);

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
					LOG_DEBUG(this->config->logger, "AudioStream::srtp", "Unsupported profile %i (%s)", profile->id, profile->id);
					break;
			}
			LOG_DEBUG(this->config->logger, "AudioStream::srtp", "Key/Salt/Master: %d/%d/%d", master_length, key_length, salt_length);


			/* Complete with SRTP setup */
			unsigned char material[master_length * 2];

			memset(material, 0x00, master_length * 2);
			unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
			/* Export keying material for SRTP */
			if(!SSL_export_keying_material(dtls->ssl_handle(), material, master_length * 2, "EXTRACTOR-dtls_srtp", 19, nullptr, 0, 0)) {
				LOG_ERROR(this->config->logger, "AudioStream::srtp", "Failed to setup SRTP key materinal!");
				return; //FIXME error handling
			}
			/* Key derivation (http://tools.ietf.org/html/rfc5764#section-4.2) */
			if(this->role == Client) {
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

			u_char remote_policy_key[master_length];
			u_char local_policy_key[master_length];
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
					LOG_ERROR(this->config->logger, "AudioStream::srtp", "Failed to create srtp session (remote)! Code %i", res);
					return; //FIXME error handling
				}
				this->srtp_in_ready = true;

				res = srtp_create(&(this->srtp_out), &(this->local_policy));
				if(res != srtp_err_status_ok) {

					LOG_ERROR(this->config->logger, "AudioStream::srtp", "Failed to create srtp session (local)! Code %i", res);
					return; //FIXME error handling
				}
				this->srtp_out_ready = true;
			}
		};

		auto certificate = pipes::TLSCertificate::generate("DataPipes", 365);
		if(!this->dtls->initialize(error, certificate, pipes::DTLS_v1, [](SSL_CTX* ctx) {
			SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32");
			return true;
		})) {
			error = "Failed to initialize tls (" + error + ")";
			return false;
		}
	}

	return true;
}

bool AudioStream::apply_sdp(const nlohmann::json& sdp, const nlohmann::json& media_entry) {
	string setup_type = media_entry["setup"];
	LOG_VERBOSE(this->config->logger, "AudioStream::apply_sdp", "Stream setup type: %s", setup_type.c_str());
	if(setup_type == "active")
		this->role = Server;
	else if(setup_type == "passive")
		this->role = Client;

	this->mid = media_entry["mid"];
	LOG_DEBUG(this->config->logger, "AudioStream::apply_sdp", "Got mid type %s", this->mid.c_str());

	{
		const nlohmann::json& ssrcs = media_entry["ssrcs"];
		for (const auto &ssrc : ssrcs) {
			string attribute = ssrc["attribute"];
			uint32_t ssrc_id = ssrc["id"];
			shared_ptr<AudioChannel> channel;
			{
				for(const auto& ch : this->remote_channels) {
					if(ch->ssrc == ssrc_id) {
						channel = ch;
						break;
					}
				}
				if(!channel) {
					channel = make_shared<AudioChannel>();
					channel->ssrc = ssrc_id;
					channel->local = false;
					this->remote_channels.push_back(channel);
				}
			}
			if(attribute == "mslabel") {
				channel->stream_id = ssrc["value"];
			} else if(attribute == "label") {
				channel->track_id = ssrc["value"];
			}
		}
		LOG_DEBUG(this->config->logger, "AudioStream::apply_sdp", "Got %u remote channels", this->remote_channels.size());
	}

	{
		size_t supported = 0;
		const nlohmann::json& rtp = media_entry["rtp"];
		for (const auto &index : rtp) {
			auto map = codec::create(index);
			if(!map) {
				//TODO log error
				continue;
			}
			if(map->local_supported()) supported += 1;
			this->offered_codecs.push_back(map);
		}
		LOG_DEBUG(this->config->logger, "AudioStream::apply_sdp", "Got %u remote offered codecs. (%u locally supported)", this->offered_codecs.size(), supported);
	}

	{
		if(media_entry.count("ext") > 0) {
			this->offered_extensions.reserve(media_entry.count("ext"));

			const nlohmann::json& exts = media_entry["ext"];
			for (const nlohmann::json &ext : exts) {
				auto extension = make_shared<HeaderExtension>();
				extension->id = ext["value"];
				extension->name = ext["uri"];

				if(ext.size() > 2)
					extension->data.reset(new nlohmann::json(std::move(ext)));

				this->offered_extensions.push_back(std::move(extension));
			}
		}
	}
	return true;
}

string AudioStream::generate_sdp() {
	ostringstream sdp;

	sdp << "a=group:BUNDLE audio\r\n"; //FIXME Bundle dynamic from request? Was "audio" before
	sdp << "a=msid-semantic: WMS DataPipes\r\n";

	string ids;
	for(const auto& codec : this->offered_codecs) {
		if(!codec->local_supported()) continue;
		ids += " " + to_string((uint32_t) codec->id);
	}
	sdp << "m=audio 9 UDP/TLS/RTP/SAVPF " << (ids.empty() ? "" : ids.substr(1)) << "\r\n";
	sdp << "c=IN IP4 0.0.0.0\r\n"; //FIXME May localhost address?
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
	sdp << "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n";

	for(const auto& codec : this->offered_codecs) {
		if(!codec->local_supported()) continue;
		codec->write_sdp(sdp);
	}

	sdp << "a=fingerprint:sha-256 " << dtls->getCertificate()->getFingerprint() << "\r\n";
	sdp << "a=setup:" << (this->role == Client ? "active" : "passive") << "\r\n";

	for(const auto& channel : this->local_channels) {
		sdp << "a=ssrc:" << channel->ssrc << " cname:" << channel->stream_id << "\r\n";
		sdp << "a=ssrc:" << channel->ssrc << " msid:" << channel->stream_id << " " << channel->track_id << "\r\n";
		sdp << "a=ssrc:" << channel->ssrc << " mslabel:" << channel->stream_id << "\r\n";
		sdp << "a=ssrc:" << channel->ssrc << " label:" << channel->track_id << "\r\n";
	}
	sdp << "a=ice-options:trickle\r\n"; //FIXME trickle only when you send the ICE candidates later
	return sdp.str();
}

bool AudioStream::reset(std::string &string) {
	if(this->dtls) this->dtls->finalize();
	this->dtls = nullptr;
	dtls_initialized = false;

	this->srtp_out_ready = false;
	if(this->srtp_out) {
		if(srtp_dealloc(this->srtp_out) != srtp_err_status_ok); //TODO error handling?
		this->srtp_out = NULL;
	}

	this->srtp_in_ready = false;
	if(this->srtp_in) {
		if(srtp_dealloc(this->srtp_in) != srtp_err_status_ok); //TODO error handling?
		this->srtp_in = NULL;
	}
	return true;
}

StreamType AudioStream::type() const {
	return CHANTYPE_AUDIO;
}

void AudioStream::process_incoming_data(const std::string &in) {
	if(!this->dtls_initialized) {
		LOG_VERBOSE(this->config->logger, "AudioStream::dtls", "incoming %i bytes", in.length());
		this->dtls->process_incoming_data(in);
	} else {
		//FIXME len check
		if(in.length() >= sizeof(protocol::rtp_header) && protocol::is_rtp((void*) in.data())) {
			this->process_rtp_data(in);
		} else if(in.length() >= sizeof(protocol::rtcp_header) && protocol::is_rtcp((void*) in.data()))
			this->process_rtcp_data(in);
		else {
			LOG_ERROR(this->config->logger, "AudioStream::process_incoming_data", "Got invalid packet (Unknown type)!");
			return;
		}
	}
}
ssize_t protocol::rtp_payload_offset(const std::string& data, size_t max_length) {
	if(data.length() < 12) return -1;

	auto header = (protocol::rtp_header *) data.data();
	size_t header_length = 12; /* without variable ssrc and extentions */
	if(header->csrccount > 0)
		header_length += header->csrccount * 4;
	if(header->extension) {
		auto header_extension = (protocol::rtp_header_extension*) &data.data()[header_length];
		auto extension_length = be16toh(header_extension->length);
		header_length += extension_length * 4 + sizeof(protocol::rtp_header_extension);
	}

	return header_length > max_length ? -1 : header_length;
}

int protocol::rtp_header_extension_parse_audio_level(const std::string& buffer, int id, int *level) {
	uint8_t byte = 0;
	if(protocol::rtp_header_extension_find(buffer, id, &byte, NULL, NULL) < 0)
		return -1;
	/* a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level */
	int v = (byte & 0x80) >> 7;
	int value = byte & 0x7F;
	if(level)
		*level = value;
	return 0;
}

/* Static helper to quickly find the extension data */
int protocol::rtp_header_extension_find(const std::string& buffer, int id, uint8_t *byte, uint32_t *word, char **ref) {
	if(buffer.length() < 12)
		return -1;
	auto* rtp = (protocol::rtp_header *) buffer.data();
	int hlen = 12;
	if(rtp->csrccount)	/* Skip CSRC if needed */
		hlen += rtp->csrccount*4;
	if(rtp->extension) {
		auto ext = (protocol::rtp_header_extension *)(buffer.data() + hlen);
		int extlen = ntohs(ext->length)*4;
		hlen += 4;
		if(buffer.length() > (hlen + extlen)) {
			/* 1-Byte extension */
			if(ntohs(ext->type) == 0xBEDE) {
				const uint8_t padding = 0x00, reserved = 0xF;
				uint8_t extid = 0, idlen;
				int i = 0;
				while(i < extlen) {
					extid = buffer[hlen+i] >> 4;
					if(extid == reserved) {
						break;
					} else if(extid == padding) {
						i++;
						continue;
					}
					idlen = (buffer[hlen+i] & 0xF)+1;
					if(extid == id) {
						/* Found! */
						if(byte)
							*byte = buffer[hlen+i+1];
						if(word)
							*word = ntohl(*(uint32_t *)(buffer.data()+hlen+i));
						if(ref)
							*ref = (char*) &buffer[hlen+i];
						return 0;
					}
					i += 1 + idlen;
				}
			}
			hlen += extlen;
		}
	}
	return -1;
}

//#define ENABLE_PROTOCOL_LOGGING
extern void alsa_replay(void* data, size_t length);
void AudioStream::process_rtp_data(const std::string &in) {
	if(!this->srtp_in_ready) {
		LOG_ERROR(this->config->logger, "AudioStream::srtp", "Got too early packet!");
		return;
	}

	auto header = (protocol::rtp_header*) in.data();
	int buflen = in.length();
	srtp_err_status_t res = srtp_unprotect(this->srtp_in, (void*) in.data(), &buflen);
	if(res != srtp_err_status_ok) {
		if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
			/* Only print the error if it's not a 'replay fail' or 'replay old' (which is probably just the result of us NACKing a packet) */
			guint32 timestamp = ntohl(header->timestamp);
			guint16 seq = ntohs(header->seq_number);
			LOG_ERROR(this->config->logger, "AudioStream::process_rtp_data", "Failed to unprotect srtp packet. Error: %i (len=%i --> %i ts=%u, seq=%i)", res, in.length(), buflen, timestamp, seq);
			return;
		}
	}

#ifdef ENABLE_PROTOCOL_LOGGING
	LOG_VERBOSE(this->config->logger, "AudioStream::process_rtp_data", "incoming %i --> %i decrypted bytes. Type %i Version %i SSRC: %u => %i Seq: %u Pad: %u Ext: %u Ver: %u Mark: %u Count: %u", in.length(), buflen, (unsigned int) header->type, (unsigned int) header->version, be32toh(header->ssrc), (unsigned int) header->csrccount, ntohs(header->seq_number), (int) header->padding, (int) header->extension, (int) header->version, (int) header->markerbit, (int) header->csrccount);
	if(header->extension) {
		auto ext = (protocol::rtp_header_extension*) (in.data() + 12);
		LOG_VERBOSE(this->config->logger, "XX", "Extenstion bytes (%x %u) %x %x %x %x", be16toh(ext->type), be16toh(ext->length), ext->data[0], ext->data[1], ext->data[2], ext->data[3]);
	}
#endif

	auto payload_offset = protocol::rtp_payload_offset(in, buflen);
	if(payload_offset > buflen); //FIXME break here

	shared_ptr<AudioChannel> channel;
	{
		auto org_ssrc = be32toh(header->ssrc);
		lock_guard<mutex> channel_lock(this->channel_lock);
		for(const auto& ch : this->remote_channels) {
			if(ch->ssrc == org_ssrc) {
				channel = ch;
				break;
			}
		}
	}
	if(!channel) {
		LOG_VERBOSE(this->config->logger, "AudioStream::srtp", "Got ssrc for an unknown channel (%u:%u)", be32toh(header->ssrc), (int) header->type);
		return;
	}

	if(!channel->codec) {
		for(const auto& codec : this->offered_codecs) {
			if(codec->id == header->type) {
				if(codec->local_supported()) {
					channel->codec = codec; //TODO fire event?
					break;
				}
			}
		}
		if(!channel->codec) {
			LOG_ERROR(this->config->logger, "AudioStream::srtp", "Channel %u (%s -> %s) does not contains a codec which is locally supported!", be32toh(header->ssrc), channel->stream_id.c_str(), channel->track_id.c_str());
			return;
		}
	}

	if(channel->codec->id != header->type) {
		LOG_ERROR(this->config->logger, "AudioStream::srtp", "Received type %u for channel %u (%s -> %s) does not match predefined type %u (%s)!", (int) header->type, be32toh(header->ssrc), channel->stream_id.c_str(), channel->track_id.c_str(), (int) channel->codec->id, channel->codec->codec.c_str());
		return;
	}

	if(this->incoming_data_handler)
		this->incoming_data_handler(channel, in.substr(0, buflen), payload_offset); //TODO Avoid copy here? Use C++17 std::string_view?
}

bool AudioStream::send_rtp_data(const shared_ptr<AudioChannel> &stream, const std::string &data, uint32_t timestamp) {
	static_assert(sizeof(protocol::rtp_header) == 12, "Invalid structure size");
	static_assert(sizeof(protocol::rtp_header_extension) == 4, "Invalid structure size");
	if(!this->srtp_out_ready) {
		LOG_ERROR(this->config->logger, "AudioStream::send_rtp_data", "Srtp not ready yet!");
		return false;
	}
	if(!stream || !stream->codec) {
		LOG_ERROR(this->config->logger, "AudioStream::send_rtp_data", "Stream hasn't a codec yet or is null!");
		return false;
	}

	auto allocated = sizeof(protocol::rtp_header) + (sizeof(protocol::rtp_header_extension) + 4) + data.length() + SRTP_MAX_TRAILER_LEN;
	allocated += allocated % 4; //Align 32 bits

	auto buffer = string(allocated, '\0');
	auto header = (protocol::rtp_header*) buffer.data();

	header->type = stream->codec->id;
	header->ssrc = htobe32(stream->ssrc);
	header->csrccount = 0;
	header->extension = 0;
	header->version = 2;
	header->padding = 0;
	header->markerbit = (uint16_t) (stream->index_packet_send == 0);
	header->timestamp = htobe32(timestamp); //FIXME!
	header->seq_number = htobe16(stream->index_packet_send);
	stream->index_packet_send += 1;

	int offset_payload = sizeof(protocol::rtp_header);

	if(header->extension) { //FIXME make this configurable?
		offset_payload += 4 + sizeof(protocol::rtp_header_extension);
		auto extension = (protocol::rtp_header_extension*) &buffer.data()[sizeof(protocol::rtp_header)];
		extension->length = htobe16(1);
		extension->type = htobe16(0xBEDE);
		extension->data[0] = 0x10; //upper: type lower: len
		extension->data[1] = 0;
		extension->data[2] = 0;
		extension->data[3] = 0;
	}

	memcpy((void*) &buffer.data()[offset_payload], data.data(), data.length());

	auto org_buflen = offset_payload + data.length();
	auto buflen = org_buflen; //SRTP_MAX_TRAILER_LEN
	srtp_err_status_t res = srtp_protect(this->srtp_out, (void*) buffer.data(), (int*) &buflen);
	if(res != srtp_err_status_ok) {
		if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
			LOG_ERROR(this->config->logger, "AudioStream::process_rtp_data", "Failed to protect srtp packet. Error: %i (len=%i --> %i)", res, buffer.length(), buflen);
			return false;
		}
	}
	assert(buffer.size() >= buflen);
#ifdef ENABLE_PROTOCOL_LOGGING
	LOG_ERROR(this->config->logger, "AudioStream::process_srtp_data", "Protect succeeed %i (len=%i --> %i | len_org=%i)", res, buffer.length(), buflen, org_buflen);
#endif
	this->send_data(buffer.substr(0, buflen)); //TODO Avoid copy here? Use C++17 std::string_view?
	return true;
}

void AudioStream::process_rtcp_data(const std::string &in) {
	auto header = (protocol::rtcp_header*) in.data();

	auto buflen = in.length();
	srtp_err_status_t res = srtp_unprotect_rtcp(this->srtp_in, (void*) in.data(), (int*) &buflen);
	if(res != srtp_err_status_ok) {
		if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
			/* Only print the error if it's not a 'replay fail' or 'replay old' (which is probably just the result of us NACKing a packet) */
			LOG_ERROR(this->config->logger, "AudioStream::process_rtcp_data", "Failed to unprotect  RTCP packet. Error %i (len=%i --> %i)", buflen, in.length(), buflen);
			return;
		}
	}
	LOG_DEBUG(this->config->logger, "AudioStream::process_rtcp_data", "Got RTCP packet of type %i and length %i", (int) header->type, (int) header->length);
}

void AudioStream::on_nice_ready() {
	this->resend_buffer();
	if(this->role == Client)
		this->dtls->do_handshake();
}