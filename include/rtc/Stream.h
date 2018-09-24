#pragma once

#include <memory>
#include "../sctp.h"

namespace pipes {
	class TLS;
	class SCTP;
};

#ifndef NLOHMANN_JSON_HPP
namespace nlohmann {
	class json;
}
#endif

namespace rtc {
	class PeerConnection;

	enum StreamType {
		CHANTYPE_APPLICATION,
		CHANTYPE_AUDIO,

		CHANTYPE_MERGED = 0xF0 //This should never happen!
	};

	typedef uint32_t StreamId;
	class Stream {
			friend class PeerConnection;

		public:
			explicit Stream(PeerConnection* /* owner */, StreamId /* stream id */);

			virtual bool initialize(std::string& /* error */) = 0;
			virtual bool apply_sdp(const nlohmann::json& /* sdp */, const nlohmann::json& /* media */) = 0;
			virtual std::string generate_sdp() = 0;
			virtual bool reset(std::string& /* error */) = 0;
			virtual const std::string& get_mid() const = 0;

			virtual StreamType type() const = 0;
			virtual StreamId stream_id() const { return this->_stream_id; }

		protected:
			virtual void process_incoming_data(const std::string& /* data */) = 0;
			virtual void on_nice_ready() = 0;
			virtual void on_dtls_initialized(const std::unique_ptr<pipes::TLS>& /* handle */) = 0;

			virtual void send_data(const std::string& /* data */);
			virtual void send_data_merged(const std::string& /* data */, bool /* dtls */);

			PeerConnection* _owner = nullptr;
			StreamId _stream_id = 0;

			bool buffer_fails = true;
			std::deque<std::string> fail_buffer;
			virtual bool resend_buffer();
	};
}