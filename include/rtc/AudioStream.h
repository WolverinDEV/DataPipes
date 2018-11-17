#pragma once

#include <map>
#include <atomic>
#include <vector>
#include <srtp2/srtp.h>
#include "Stream.h"

namespace rtc {
	/* Most copied from janus */
	namespace protocol {
		/*! \brief RTP Header (http://tools.ietf.org/html/rfc3550#section-5.1) */
		struct rtp_header
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

		struct rtp_header_extension {
			uint16_t type;
			uint16_t length;
			uint8_t data[0];
		};

		/*! \brief RTCP Packet Types (http://www.networksorcery.com/enp/protocol/rtcp.htm) */
		enum rtcp_type : uint8_t {
			RTCP_FIR = 192,
			RTCP_SR = 200, /* SR, sender report */
			RTCP_RR = 201, /* RR, receiver report */
			RTCP_SDES = 202,
			RTCP_BYE = 203,
			RTCP_APP = 204,
			RTCP_RTPFB = 205,
			RTCP_PSFB = 206,
			RTCP_XR = 207,
		};


/*! \brief RTCP Header (http://tools.ietf.org/html/rfc3550#section-6.1) */
		struct rtcp_header
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
		};

		inline bool is_rtcp(void* buf) {
			auto header = (protocol::rtp_header *) buf;
			return ((header->type >= 64) && (header->type < 96));
		}

		inline bool is_rtp(void* buf) {
			auto header = (protocol::rtp_header *) buf;
			return ((header->type < 64) || (header->type >= 96));
		}

		extern ssize_t rtp_payload_offset(const pipes::buffer_view& /* data */, size_t /* max_length */);
		extern int rtp_header_extension_find(const pipes::buffer_view& /* buffer */, int id, uint8_t *byte, uint32_t *word, char **ref);
		extern int rtp_header_extension_parse_audio_level(const pipes::buffer_view& /* buffer */, int id, int *level);
	}

	struct HeaderExtension {
		bool local = false;

		std::string name;
		uint8_t id;
		std::string direction;
		std::string config;
	};

	namespace codec {
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
		std::shared_ptr<codec::TypedAudio> codec;

		std::string stream_id;
		std::string track_id;

		/* just to keep track of some variables (for external use) */
		uint32_t timestamp_last_send = 0;
		uint32_t timestamp_last_receive = 0;

		uint32_t index_packet_send = 0;
		uint32_t index_packet_receive = 0;

		void* user_ptr = nullptr;
	};

	class MergedStream;
	class AudioStream : public Stream {
			friend class PeerConnection;
			friend class MergedStream;
		public:
			struct Configuration {
				std::shared_ptr<pipes::Logger> logger;
			};
			/** buffer contains the full rtp packet inc. header and extensions **/
			typedef std::function<void(const std::shared_ptr<AudioChannel>& /* channel */, const pipes::buffer_view& /* buffer */, size_t /* payload offset */)> callback_data;

			AudioStream(PeerConnection* /* owner */, StreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
			virtual ~AudioStream();

			bool initialize(std::string &string) override;

			bool apply_sdp(const nlohmann::json& /* sdp */, const nlohmann::json& /* media */) override;
			const std::string& get_mid() const override { return this->mid; }

			std::string generate_sdp() override;

			bool reset(std::string &string) override;

			StreamType type() const override;


			bool send_rtp_data(const std::shared_ptr<AudioChannel>& /* channel */, const pipes::buffer_view& /* data */, uint32_t /* timestamp */);
			callback_data incoming_data_handler = nullptr;

			std::deque<std::shared_ptr<codec::TypedAudio>> find_codec_by_name(const std::string& /* name */);
			/**
			 * @param direction mask:
			 * 		first byte: incoming
			 * 		second byte: outgoing
			 *
		 	 * @attention
		 	 * 		If mask := 3, local channels will be scanned first and may override remote channels
			 */
			std::shared_ptr<AudioChannel> find_channel_by_id(uint32_t /* src */, uint8_t /* direction mask */ = 3);
			/**
			 * @param direction mask:
			 * 		first byte: incoming
			 * 		second byte: outgoing
			 */
			std::deque<std::shared_ptr<AudioChannel>> list_channels(uint8_t /* direction mask */ = 3);
			/**
			 * @param direction mask:
			 * 		first byte: incoming
			 * 		second byte: outgoing
			 *
		 	 * @attention
		 	 * 		If mask := 3, local extensions will be scanned first and may override remote channels
			 */
			std::shared_ptr<HeaderExtension> find_extension_by_id(uint8_t /* id */,uint8_t /* direction mask */ = 3);
			/**
			 * @param direction mask:
			 * 		first byte: incoming
			 * 		second byte: outgoing
			 */
			std::deque<std::shared_ptr<HeaderExtension>> list_extensions( uint8_t /* direction mask */ = 3);

			void register_local_channel(const std::string& /* stream id */, const std::string& /* track id */, const std::shared_ptr<codec::TypedAudio>& /* type */);
			std::shared_ptr<HeaderExtension> register_local_extension(const std::string& /* name/uri */, const std::string& /* direction */ = "", const std::string& /* config */ = "");
		protected:
			void on_nice_ready() override;
			void on_dtls_initialized(const std::unique_ptr<pipes::TLS> &ptr) override;
		protected:
			void process_incoming_data(const pipes::buffer_view&string) override;
			void process_rtp_data(const pipes::buffer_view & /* data */);
			void process_rtcp_data(const pipes::buffer_view & /* data */);
		private:
			std::shared_ptr<Configuration> config;

			bool dtls_initialized = false;
			std::unique_ptr<pipes::TLS> dtls;

			srtp_t srtp_in = nullptr;
			bool srtp_in_ready = false;
			srtp_t srtp_out = nullptr;
			bool srtp_out_ready = false;
			srtp_policy_t remote_policy;
			srtp_policy_t local_policy;

			std::string mid;
			enum Role { Client, Server } role = Client;

			std::deque<std::shared_ptr<codec::TypedAudio>> offered_codecs;
			std::vector<std::shared_ptr<HeaderExtension>> remote_extensions;
			std::vector<std::shared_ptr<HeaderExtension>> local_extensions;

			std::mutex channel_lock;
			std::vector<std::shared_ptr<AudioChannel>> remote_channels;
			std::vector<std::shared_ptr<AudioChannel>> local_channels;
	};

}