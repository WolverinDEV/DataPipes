#pragma once

#include <map>
#include <srtp/srtp.h>
#include "Stream.h"
#include <opus/opus.h>
#include <atomic>

namespace rtc {
	/*! \brief RTP Header (http://tools.ietf.org/html/rfc3550#section-5.1) */
	/* Copied from janus */
	struct RTPHeader
	{
#if __BYTE_ORDER == __BIG_ENDIAN
		uint16_t version:2;
		uint16_t padding:1;
		uint16_t extension:1;
		uint16_t csrccount:4;
		uint16_t markerbit:1;
		uint16_t type:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
		uint16_t csrccount:4;
		uint16_t extension:1;
		uint16_t padding:1;
		uint16_t version:2;
		uint16_t type:7;
		uint16_t markerbit:1;
#endif
		uint16_t seq_number;
		uint32_t timestamp;
		uint32_t ssrc;
		uint32_t csrc[0];
	};

	struct RTPHeaderExtension {
		uint16_t type;
		uint16_t length;
		uint8_t data[0];
	};

	namespace rtcp {
		/*! \brief RTCP Packet Types (http://www.networksorcery.com/enp/protocol/rtcp.htm) */
		/* Copied from janus */
		typedef enum {
			RTCP_FIR = 192,
			RTCP_SR = 200, /* SR, sender report */
			RTCP_RR = 201, /* RR, receiver report */
			RTCP_SDES = 202,
			RTCP_BYE = 203,
			RTCP_APP = 204,
			RTCP_RTPFB = 205,
			RTCP_PSFB = 206,
			RTCP_XR = 207,
		} rtcp_type;


/*! \brief RTCP Header (http://tools.ietf.org/html/rfc3550#section-6.1) */
/* Copied from janus */
		typedef struct rtcp_header
		{
#if __BYTE_ORDER == __BIG_ENDIAN
			uint16_t version:2;
	uint16_t padding:1;
	uint16_t rc:5;
	uint16_t type:8;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t rc:5;
			uint16_t padding:1;
			uint16_t version:2;
			uint16_t type:8;
#endif
			uint16_t length:16;
		} rtcp_header;
	}


	namespace rtp { //FIXME wrong namespace name?
		struct TypedAudio {
			enum {
				UNSET = 0,
				UNKNOWN,
				OPUS
			} type;

			uint8_t id;
			std::string codec;

			virtual bool write_sdp(std::ostringstream& /* ss */) = 0;
			virtual bool local_supported() const = 0;
		};


		extern std::shared_ptr<TypedAudio> create(const nlohmann::json& /* sdp */);

		struct OpusAudio : public TypedAudio {
			uint16_t sample_rate = 0;
			std::string encoding;

			bool write_sdp(std::ostringstream& /* ss */) override;
			bool local_supported() const override;
		};

		struct UnknownAudio : public TypedAudio {
			bool write_sdp(std::ostringstream& /* ss */) override;
			bool local_supported() const override;
		};
	}

	struct AudioChannel {
		bool local = false;

		uint32_t ssrc = 0;
		std::shared_ptr<rtp::TypedAudio> codec;

		std::string stream_id;
		std::string track_id;

		/* just to keep track of some variables (for external use) */
		uint32_t timestamp_last_send = 0;
		uint32_t timestamp_last_receive = 0;

		uint32_t index_packet_send = 0;
		uint32_t index_packet_receive = 0;

		void* user_ptr = nullptr;
	};

	class AudioStream : public Stream {
			friend class PeerConnection;
		public:
			struct Configuration {
				std::shared_ptr<pipes::Logger> logger;
			};
			/** buffer contains the full rtp packet inc. header and extensions **/
			typedef std::function<void(const std::shared_ptr<AudioChannel>& /* channel */, const std::string& /* buffer */, size_t /* payload offset */)> callback_data;

			AudioStream(PeerConnection* /* owner */, StreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
			virtual ~AudioStream();

			bool initialize(std::string &string) override;

			bool apply_sdp(const nlohmann::json& /* sdp */, const nlohmann::json& /* media */) override;
			const std::string& get_mid() const { return this->mid; }

			std::string generate_sdp() override;

			bool reset(std::string &string) override;

			StreamType type() const override;


			void send_rtp_data(const std::shared_ptr<AudioChannel>& /* channel */, const std::string& /* data */, uint32_t /* timestamp */);
			callback_data incoming_data_handler;

			std::deque<std::shared_ptr<rtp::TypedAudio>> find_codec_by_name(const std::string& /* name */);

			void register_local_channel(const std::string& /* stream id */, const std::string& /* track id */, const std::shared_ptr<rtp::TypedAudio>& /* type */);
			/**
			 * @param direction mask:
			 * 		first byte: incoming
			 * 		second byte: outgoing
			 */
			std::shared_ptr<AudioChannel> find_channel_by_id(uint32_t /* src */, uint8_t /* direction mask */ = 3);
			/**
			 * @param direction mask:
			 * 		first byte: incoming
			 * 		second byte: outgoing
			 */
			std::deque<std::shared_ptr<AudioChannel>> list_channels(uint8_t /* direction mask */ = 3);

		protected:
			void on_nice_ready() override;

		protected:
			void process_incoming_data(const std::string &string) override;
			void process_srtp_data(const std::string& /* data */);
			void process_srtp_rtcp_data(const std::string& /* data */);
		private:
			std::shared_ptr<Configuration> config;

			bool dtls_initialized = false;
			std::unique_ptr<pipes::TLS> dtls;

			srtp_t srtp_in;
			bool srtp_in_ready = false;
			srtp_t srtp_out;
			bool srtp_out_ready = false;
			srtp_policy_t remote_policy;
			srtp_policy_t local_policy;

			std::string mid;
			enum Role { Client, Server } role = Client;

			OpusDecoder* opus_decoder = nullptr;

			std::deque<std::shared_ptr<rtp::TypedAudio>> offered_codecs;

			std::mutex channel_lock;
			std::vector<std::shared_ptr<AudioChannel>> remote_channels;
			std::vector<std::shared_ptr<AudioChannel>> local_channels;
	};

}