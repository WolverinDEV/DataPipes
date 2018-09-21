#pragma once

#include <map>
#include <memory>
#include <utility>
#include "../sctp.h"
#include "include/tls.h"
#include "../misc/logger.h"
#include "NiceWrapper.h"
#include "Stream.h"

namespace rtc {
	class ApplicationStream;
	class AudioStream;

	struct IceCandidate {
		std::string candidate;
		std::string sdpMid;
		std::string sdpMLineIndex;
	};

	class PeerConnection {
			friend class Stream;
		public:
			struct Config {
				std::shared_ptr<pipes::Logger> logger;
				std::shared_ptr<NiceWrapper::Config> nice_config;

				size_t max_data_channels = 1024;

				struct {
					uint16_t local_port = 5000;
				} sctp;
			};
			struct IceCandidate {
				IceCandidate(std::string candidate, std::string sdpMid, int sdpMLineIndex)
						: candidate(std::move(candidate)), sdpMid(std::move(sdpMid)), sdpMLineIndex(sdpMLineIndex) {}
				std::string candidate;
				std::string sdpMid;
				int sdpMLineIndex;
			};
			enum ConnectionComponent {
				BASE,
				NICE,
				DTLS,
				SCTP
			};
			typedef std::function<void(const IceCandidate&)> cb_ice_candidate;
			typedef std::function<void(ConnectionComponent /* component */, const std::string& /* reason */)> cb_setup_fail;

			typedef std::function<void(const std::shared_ptr<Stream>& /* stream */)> cb_new_stream;

			PeerConnection(const std::shared_ptr<Config>& config);
			virtual ~PeerConnection();

			std::shared_ptr<Config> configuration() { return this->config; }
			void reset();
			bool initialize(std::string& /* error */);

			//TODO vice versa (we create a offer and parse the answer?)
			bool apply_offer(std::string& /* error */, const std::string& /* offer */);
			int apply_ice_candidates(const std::deque<std::shared_ptr<IceCandidate>>& /* candidates */);
			cb_ice_candidate callback_ice_candidate;

			std::string generate_answer(bool /* candidates */);

			cb_setup_fail callback_setup_fail;
			cb_new_stream callback_new_stream;

			std::deque<std::shared_ptr<Stream>> availible_streams(); /* only valid result after apply_offer(...) */
		protected:
			virtual void on_nice_ready();
			virtual void trigger_setup_fail(ConnectionComponent /* component */, const std::string& /* reason */);
		private:
			std::shared_ptr<Config> config;

			std::unique_ptr<NiceWrapper> nice;
			std::shared_ptr<ApplicationStream> stream_application;
			std::shared_ptr<AudioStream> stream_audio;

			std::deque<std::shared_ptr<Stream>> sdp_media_lines;
			inline int sdp_mline_index(const std::shared_ptr<Stream>& stream) {
				int index = 0;
				for(const auto& entry : sdp_media_lines)
					if(entry == stream) return index;
					else index++;
				return -1;
			}

			bool create_application_stream(std::string& error);
			bool create_audio_stream(std::string& error);
	};
}