#pragma once

#include "pipes/tls.h"
#include "../misc/logger.h"
#include "./NiceWrapper.h"
#include "pipes/rtc/channels/Channel.h"

#include <map>
#include <memory>
#include <utility>

namespace rtc {
	class ApplicationChannel;
	class AudioChannel;
	class VideoChannel;
	class DTLSHandler;

	struct IceCandidate {
		IceCandidate(std::string candidate, std::string sdpMid, int sdpMLineIndex)
				: candidate(std::move(candidate)), sdpMid(std::move(sdpMid)), sdpMLineIndex(sdpMLineIndex) {}
		std::string candidate;
		std::string sdpMid;
		int sdpMLineIndex;

		[[nodiscard]] inline bool is_finished_candidate() const { return this->candidate.empty(); }
	};
	class PeerConnection {
			friend class Channel;
			friend class DTLSHandler;
		public:
			struct Config {
				std::shared_ptr<pipes::Logger> logger;
				std::shared_ptr<NiceWrapper::Config> nice_config;

				size_t max_data_channels = 1024;
				bool print_parse_sdp = false;

				struct {
					uint16_t local_port = 5000;
				} sctp;
			};
			enum ConnectionComponent {
				BASE,
				NICE,
				DTLS,
				SCTP
			};

			/**
			 * All callbacks will be called within the gmain_loop supplied by the config.
			 * Do not deallocate the PeerConnection within this loop!
			 */
			typedef std::function<void(const IceCandidate& /* candidate */)> cb_ice_candidate;
			typedef std::function<void(ConnectionComponent /* component */, const std::string& /* reason */)> cb_setup_fail;
			typedef std::function<void(const std::shared_ptr<Channel>& /* stream */)> cb_new_stream;

			explicit PeerConnection(std::shared_ptr<Config>  /* config */);
			virtual ~PeerConnection();

            [[nodiscard]] std::shared_ptr<Config> configuration() { return this->config; }
			void reset();
            [[nodiscard]] bool initialize(std::string& /* error */);

			//TODO vice versa (we create a offer and parse the answer?)
            [[nodiscard]] bool apply_offer(std::string& /* error */, const std::string& /* offer */);
            [[nodiscard]] std::string generate_answer(bool /* candidates */);

            int apply_ice_candidates(const std::deque<std::shared_ptr<IceCandidate>>& /* candidates */);
            void remote_candidates_finished();

            cb_ice_candidate callback_ice_candidate;
			cb_setup_fail callback_setup_fail;
			cb_new_stream callback_new_stream;

            [[nodiscard]] inline std::vector<std::shared_ptr<Channel>> available_channels() {
			    std::lock_guard lock{this->stream_lock};
			    return this->streams;
			}

		private:
			std::shared_ptr<Config> config;

			std::shared_ptr<NiceWrapper> nice;

			std::shared_mutex stream_lock{};
			std::vector<std::shared_ptr<Channel>> streams{}; /* streams in order with the media line indexes */
			std::vector<std::shared_ptr<DTLSHandler>> dtls_streams{};

            inline int sdp_mline_index(const std::shared_ptr<Channel>& stream) {
                int index = 0;
                for(const auto& entry : this->streams)
                    if(entry == stream) return index;
                    else index++;
                return -1;
            }

            std::shared_ptr<DTLSHandler> find_dts_pipe(NiceStreamId /* stream */);
            std::vector<std::shared_ptr<Channel>> find_streams_from_nice_stream(NiceStreamId /* stream */);
			void handle_nice_data(NiceStreamId /* stream */, const pipes::buffer_view& /* data */);
            void handle_dtls_data(NiceStreamId /* stream */, const pipes::buffer_view& /* data */);
	};
}