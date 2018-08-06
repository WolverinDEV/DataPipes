#pragma once

#include <string>
#include <memory>
#include <deque>
#include <thread>
#include "../misc/logger.h"

extern "C" {
	#include <nice/agent.h>
}

namespace rtc {
	struct RTCIceServer {
		std::string host;
		uint16_t port;
	};

	struct NiceStream {
		uint32_t stream_id = 0;
		bool ready = false;
	};

	class NiceWrapper {
		public:
			typedef std::function<void(const std::string&)> cb_candidate;
			typedef std::function<void(const std::string&)> cb_recive;
			typedef std::function<void()> cb_ready;
			typedef std::function<void()> cb_failed;

			struct Config {
				std::deque<RTCIceServer> ice_servers;
				std::pair<uint16_t, uint16_t> ice_port_range;

				std::string ice_ufrag;
				std::string ice_pwd;

				std::shared_ptr<GMainLoop> main_loop;
			};

			NiceWrapper(const std::shared_ptr<Config>& /* config */);
			virtual ~NiceWrapper();

			bool initialize(std::string& /* error */);
			void finalize();

			ssize_t apply_remote_ice_candidates(const std::deque<std::string>& /* candidates */);
			bool apply_remote_sdp(std::string& /* error */, std::string /* sdp */);
			std::string generate_local_sdp(bool /* with candidates */);


			void send_data(guint /* stream */, guint /* component */, const std::string& /* buffer */);

			void set_callback_local_candidate(const cb_candidate& /* callback */);
			void set_callback_recive(const cb_recive& /* callback */);
			void set_callback_ready(const cb_ready& /* callback */);
			void set_callback_failed(const cb_failed& /* callback */);

			uint32_t stream_id() { return this->stream ? this->stream->stream_id : 0; }

			std::shared_ptr<pipes::Logger> logger() { return this->_logger; }
			void logger(const std::shared_ptr<pipes::Logger>& logger) { this->_logger = logger; }
		private:
			static void cb_recived(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data);
			static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data);
			static void cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer user_data);
			static void cb_new_local_candidate(NiceAgent *agent, NiceCandidate *candidate, gpointer user_data);
			static void cb_new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *lcandidate, NiceCandidate *rcandidate, gpointer user_data);
			static void cb_transport_writeable(NiceAgent *agent, guint sid, guint cid, gpointer data);

		protected:
			virtual void on_data_recived(guint /* stream */, guint /* component */, void* /* buffer */, size_t /* length */);

			virtual void on_gathering_done();
			virtual void on_ice_ready();
			virtual void on_selected_pair(guint /* stream */, guint /* component */, NiceCandidate* /* local candidate */, NiceCandidate* /* remote candidate */);
			virtual void on_state_change(guint /* stream */, guint /* component */, guint /* state */);
			virtual void on_local_ice_candidate(const std::string& /* candidate */);
			virtual void on_transport_writeable(guint /* stream */, guint /* component */);
		private:
			std::shared_ptr<pipes::Logger> _logger;
			std::shared_ptr<Config> config;

			std::unique_ptr<NiceAgent, void (*)(gpointer)> agent;
			std::shared_ptr<GMainLoop> loop;
			bool own_loop = false;

			std::thread g_main_loop_thread;
			std::unique_ptr<NiceStream> stream;

			cb_recive callback_recive;
			cb_ready callback_ready;
			cb_candidate callback_local_candidate;
			cb_failed callback_failed;
	};
}