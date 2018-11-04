#pragma once

#include <string>
#include <memory>
#include <deque>
#include <thread>
#include <mutex>
#include "../buffer.h"
#include "../misc/logger.h"

extern "C" {
	#include <nice/agent.h>
}

namespace rtc {
	struct RTCIceServer {
		std::string host;
		uint16_t port;
	};

	typedef uint32_t StreamId;
	struct NiceStream {
		typedef std::function<void(const pipes::buffer_view&)> cb_receive;
		typedef std::function<void()> cb_ready;

		uint32_t stream_id = 0xFFFF;
		bool ready = false;
		cb_receive callback_receive;
		cb_ready callback_ready;
	};

	struct LocalSdpEntry {
		int index;
		std::string media;
		std::string connection;
		std::string ice_ufrag;
		std::string ice_pwd;
		std::deque<std::string> candidates;

		union {
			struct {
				bool media :1;
				bool connection :1;
				bool ice_ufrag :1;
				bool ice_pwd :1;
				bool candidates :1;
			} has;
			uint8_t has_bitset;
		};
	};

	class NiceWrapper {
		public:
			typedef std::function<void(const std::shared_ptr<NiceStream>& /* stream */, const std::string& /* sdp */)> cb_candidate;
			typedef std::function<void(const std::shared_ptr<NiceStream>& /* stream */)> cb_failed;

			struct Config {
				std::deque<RTCIceServer> ice_servers;
				std::pair<uint16_t, uint16_t> ice_port_range;

				std::string ice_ufrag;
				std::string ice_pwd;

				std::shared_ptr<GMainLoop> main_loop;
			};

			explicit NiceWrapper(const std::shared_ptr<Config>& /* config */);
			virtual ~NiceWrapper();

			bool initialize(std::string& /* error */);
			void finalize();

			bool gather_candidates(const std::shared_ptr<NiceStream>& /* stream */);
			ssize_t apply_remote_ice_candidates(const std::shared_ptr<NiceStream>& /* stream */, const std::deque<std::string>& /* candidates */);
			bool apply_remote_sdp(std::string& /* error */, std::string /* sdp */);
			std::deque<std::unique_ptr<LocalSdpEntry>> generate_local_sdp(bool /* with candidates */);


			bool send_data(guint /* stream */, guint /* component */, const pipes::buffer_view& /* buffer */);

			void set_callback_local_candidate(const cb_candidate& /* callback */);
			void set_callback_failed(const cb_failed& /* callback */);

			std::shared_ptr<NiceStream> find_stream(StreamId /* id */);
			std::shared_ptr<NiceStream> add_stream(const std::string& /* name */);
			std::deque<std::shared_ptr<NiceStream>> available_streams();

			std::shared_ptr<pipes::Logger> logger() { return this->_logger; }
			void logger(const std::shared_ptr<pipes::Logger>& logger) { this->_logger = logger; }
		private:
			static void cb_received(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data);
			static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data);
			static void cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer user_data);
			static void cb_new_local_candidate(NiceAgent *agent, guint stream_id, guint component_id, gchar* foundation, gpointer user_data);
			static void cb_new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *lcandidate, NiceCandidate *rcandidate, gpointer user_data);
			static void cb_transport_writeable(NiceAgent *agent, guint sid, guint cid, gpointer data);

		protected:
			virtual void on_data_received(guint /* stream */, guint /* component */, void * /* buffer */, size_t /* length */);

			virtual void on_gathering_done(guint stream_id);
			virtual void on_selected_pair(guint /* stream */, guint /* component */, NiceCandidate* /* local candidate */, NiceCandidate* /* remote candidate */);
			virtual void on_state_change(guint /* stream */, guint /* component */, guint /* state */);
			virtual void on_local_ice_candidate(guint /* stream */, guint /* component */, gchar* /* foundation */);
			virtual void on_transport_writeable(guint /* stream */, guint /* component */);
		private:
			std::recursive_mutex io_lock;
			std::shared_ptr<pipes::Logger> _logger;
			std::shared_ptr<Config> config;

			std::unique_ptr<NiceAgent, void (*)(gpointer)> agent;
			std::shared_ptr<GMainLoop> loop;
			bool own_loop = false;

			std::thread g_main_loop_thread;
			std::recursive_mutex streams_lock;
			std::deque<std::shared_ptr<NiceStream>> streams;

			cb_candidate callback_local_candidate;
			cb_failed callback_failed;
	};
}