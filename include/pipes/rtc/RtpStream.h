#pragma once

#include "./Stream.h"
#include "./Protocol.h"
#include "../misc/logger.h"

#include <cstdint>
#include <sstream>
#ifdef SRTP_VERSION_1
    #include <srtp/srtp.h>
#else
    #include <srtp2/srtp.h>
#endif

namespace pipes {
	class TLSCertificate;
}

namespace rtc {
	namespace codec {
		typedef uint8_t id_t;

		struct Codec {
			enum {
				UNSET = 0,
				UNKNOWN,

				OPUS
			} type = UNSET;

			id_t id = 0;
			std::string codec;
			int32_t rate = 0;

			std::vector<std::string> parameters;

			bool accepted = false;
			virtual bool write_sdp(std::ostringstream& /* ss */) = 0;
			virtual bool local_accepted();
		};


		extern std::shared_ptr<Codec> create(const json& /* sdp */);

		struct UnknownCodec : public Codec {
			public:
				bool write_sdp(std::ostringstream& /* ss */) override;

			protected:
				bool write_sdp_rtpmap(std::ostringstream& /* ss */);
				bool write_sdp_fmtp(std::ostringstream& /* ss */);
		};

		struct OpusCodec : public UnknownCodec {
			uint8_t encoding = 2; /* must be 2 */
			bool write_sdp(std::ostringstream& /* ss */) override;
		};
	}

	struct Channel {
		bool local = false;

		uint32_t ssrc = 0;
		std::shared_ptr<codec::Codec> codec;

		std::string stream_id;
		std::string track_id;

		/* just to keep track of some variables (for external use) */
		uint32_t timestamp_last_send = 0;
		uint32_t timestamp_last_receive = 0;

		uint32_t index_packet_send = 0;
		uint32_t index_packet_receive = 0;

		void* user_ptr = nullptr;
	};

	struct direction {
		enum value : uint8_t {
			incoming = 0x01,
			outgoing = 0x02,
			bidirectional = 0x03
		};
	};

	class MergedStream;
	class RTPStream : public Stream {
			friend class PeerConnection;
		public:
			struct Configuration {
				std::shared_ptr<pipes::Logger> logger;
			};

			/** buffer contains the full rtp packet inc. header and extensions **/
			typedef std::function<void(const std::shared_ptr<Channel>& /* codec */, const pipes::buffer_view& /* buffer */, size_t /* payload offset */)> callback_data;

			RTPStream(PeerConnection* /* owner */, NiceStreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
			virtual ~RTPStream();

			bool initialize(std::string &string) override;

			bool apply_sdp(const json& /* sdp */, const json& /* media */) override;
			const std::string& get_mid() const override { return this->mid; }

			std::string generate_sdp() override;
			bool reset(std::string &string) override;

			bool send_rtp_data(const std::shared_ptr<Channel>& /* channel */, const pipes::buffer_view& /* data */, uint32_t /* timestamp */, bool /* contains extension */ = false, int /* marker bit */ = -1);
			callback_data incoming_data_handler = nullptr;

			std::deque<std::shared_ptr<codec::Codec>> find_codecs_by_name(const std::string& /* name */);
			std::shared_ptr<codec::Codec> find_codec_by_id(const codec::id_t& /* id */);
			std::deque<std::shared_ptr<codec::Codec>> list_codecs();

			std::shared_ptr<Channel> find_channel_by_id(uint32_t /* src */, direction::value /* direction mask */ = direction::bidirectional);
			std::deque<std::shared_ptr<Channel>> list_channels(direction::value /* direction mask */ = direction::bidirectional);

			std::shared_ptr<HeaderExtension> find_extension_by_id(uint8_t /* id */,direction::value /* direction mask */ = direction::bidirectional);
			std::deque<std::shared_ptr<HeaderExtension>> list_extensions(direction::value /* direction mask */ = direction::bidirectional);

			void register_local_channel(const std::string& /* stream id */, const std::string& /* track id */, const std::shared_ptr<codec::Codec>& /* type */);
			std::shared_ptr<HeaderExtension> register_local_extension(const std::string& /* name/uri */, const std::string& /* direction */ = "", const std::string& /* config */ = "", uint8_t /* supposed id */ = 0);

		protected:
			/* some events */
            void on_dtls_initialized(const std::shared_ptr<DTLSPipe>&ptr) override;

			/* some data processors */
            bool process_incoming_dtls_data(const pipes::buffer_view& /* data */) override;
            bool process_incoming_rtp_data(RTPPacket& /* data */) override;
            bool process_incoming_rtcp_data(RTCPPacket& /* data */) override;

            void process_rtp_data(const std::shared_ptr<Channel>& channel, const pipes::buffer_view & /* data */);
            void process_rtcp_data(const std::shared_ptr<Channel>& channel, const pipes::buffer_view & /* data */);

		protected: /* methods to implement */
			virtual std::string sdp_media_type() const = 0;

		private:
			std::shared_ptr<Configuration> config;

			srtp_t srtp_in = nullptr;
			bool srtp_in_ready = false;
			srtp_t srtp_out = nullptr;
			bool srtp_out_ready = false;
			srtp_policy_t remote_policy;
			srtp_policy_t local_policy;

			std::deque<std::shared_ptr<codec::Codec>> offered_codecs;
			std::vector<std::shared_ptr<HeaderExtension>> remote_extensions;
			std::vector<std::shared_ptr<HeaderExtension>> local_extensions;

			std::mutex channel_lock;
			std::vector<std::shared_ptr<Channel>> remote_channels;
			std::vector<std::shared_ptr<Channel>> local_channels;
	};
}