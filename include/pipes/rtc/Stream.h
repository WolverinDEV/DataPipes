#pragma once

#include "pipes/buffer.h"
#include <cstddef>
#include <string>
#include <memory>
#include <shared_mutex>
#include <deque>

namespace pipes {
	class TLS;
	class SCTP;
}

namespace rtc {
	class PeerConnection;
	class DTLSPipe;
	class RTPPacket;
    class RTCPPacket;
    struct json;

	enum StreamType {
		CHANTYPE_APPLICATION,
		CHANTYPE_AUDIO,
		CHANTYPE_VIDEO,

		CHANTYPE_MERGED = 0xF0 //This should never happen!
	};

	typedef uint32_t NiceStreamId;
	class Stream {
			friend class PeerConnection;

		public:
			explicit Stream(PeerConnection* /* owner */, NiceStreamId /* nice stream id */);

			virtual bool initialize(std::string& /* error */) = 0;
			virtual bool apply_sdp(const json& /* sdp */, const json& /* media */) = 0;
			virtual std::string generate_sdp() = 0;
			virtual bool reset(std::string& /* error */) = 0;
			virtual const std::string& get_mid() const = 0;

			virtual StreamType type() const = 0;
			virtual NiceStreamId nice_stream_id() const { return this->_nice_stream_id; }

		protected:
			virtual bool process_incoming_dtls_data(const pipes::buffer_view& /* data */) = 0;
            virtual bool process_incoming_rtp_data(RTPPacket& /* data */) = 0;
            virtual bool process_incoming_rtcp_data(RTCPPacket& /* data */) = 0;
			virtual void on_dtls_initialized(const std::shared_ptr<DTLSPipe>& /* handle */) = 0;

			/**
			 * @note This function is thread save
			 */
			virtual void send_data(const pipes::buffer_view& /* data */, bool /* dtls encrypt */ = true);

			std::shared_mutex _owner_lock;
			PeerConnection* _owner = nullptr;
			NiceStreamId _nice_stream_id{0};

			std::string mid;
	};
}