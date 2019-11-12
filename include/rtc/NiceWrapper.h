#pragma once

#include <string>
#include <memory>
#include <deque>
#include <thread>
#include <mutex>

#include "../buffer.h"
#include "../misc/logger.h"

typedef struct _GSList GSList;
typedef struct _GMainLoop GMainLoop;

typedef struct _NiceAgent NiceAgent;
typedef struct _NiceCandidate NiceCandidate;

namespace rtc {
	namespace g {
#ifndef __G_TYPES_H__
		#define _(t, ot) typedef ot t
#else
		#define _(t, ot) typedef ::g ##t t
#endif
		_(uint, unsigned int);
		_(_char, char);
		_(pointer, void*);
#undef _
	}

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

		/* will be applied to the nice stream when gathering candidates */
		GSList* ice_remote_candidate_list = nullptr; /* protected with the IO lock */
		GSList* ice_local_candidate_list = nullptr; /* protected with the IO lock */
		bool negotiation_required = false;
		bool gathering_done = false;

		~NiceStream();
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
			typedef std::function<void(const std::shared_ptr<NiceStream>& /* stream */, const std::vector<std::string>& /* sdps */, bool /* more candidates */)> cb_candidate;
			typedef std::function<void(const std::shared_ptr<NiceStream>& /* stream */)> cb_failed;

			struct Config {
				std::deque<RTCIceServer> ice_servers;
				std::pair<uint16_t, uint16_t> ice_port_range;

				std::string ice_ufrag;
				std::string ice_pwd;

				std::shared_ptr<GMainLoop> main_loop;

				bool allow_ice_tcp = true;
				bool allow_ice_udp = true;

				bool use_upnp = false;
			};

			explicit NiceWrapper(const std::shared_ptr<Config>& /* config */);
			virtual ~NiceWrapper();

			bool initialize(std::string& /* error */);
			void finalize();


			bool apply_remote_sdp(std::string& /* error */, std::string /* sdp */);
			std::deque<std::unique_ptr<LocalSdpEntry>> generate_local_sdp(bool /* with candidates */);

			bool gather_candidates(const std::shared_ptr<NiceStream>& /* stream */); /* generate a list of candidates */
			ssize_t apply_remote_ice_candidates(const std::shared_ptr<NiceStream>& /* stream */, const std::deque<std::string>& /* candidates */);
			bool execute_negotiation(const std::shared_ptr<rtc::NiceStream> &stream); /* sets the remote candidates and begin to connect */


			bool send_data(g::uint /* stream */, g::uint /* component */, const pipes::buffer_view& /* buffer */);

			void set_callback_local_candidate(const cb_candidate& /* callback */);
			void set_callback_failed(const cb_failed& /* callback */);

			std::shared_ptr<NiceStream> find_stream(StreamId /* id */);
			std::shared_ptr<NiceStream> add_stream(const std::string& /* name */);
			std::deque<std::shared_ptr<NiceStream>> available_streams();

			std::shared_ptr<pipes::Logger> logger() { return this->_logger; }
			void logger(const std::shared_ptr<pipes::Logger>& logger) { this->_logger = logger; }
		private:
			static void cb_received(NiceAgent *agent, g::uint stream_id, g::uint component_id, g::uint len, g::_char *buf, g::pointer user_data);
			static void cb_candidate_gathering_done(NiceAgent *agent, g::uint stream_id, g::pointer user_data);
			static void cb_component_state_changed(NiceAgent *agent, g::uint stream_id, g::uint component_id, g::uint state, g::pointer user_data);
			static void cb_new_local_candidate(NiceAgent *agent, g::uint stream_id, g::uint component_id, g::_char* foundation, g::pointer user_data);
			static void cb_new_selected_pair(NiceAgent *agent, g::uint stream_id, g::uint component_id, NiceCandidate *lcandidate, NiceCandidate *rcandidate, g::pointer user_data);
			static void cb_transport_writeable(NiceAgent *agent, g::uint sid, g::uint cid, g::pointer data);

		protected:
			virtual void on_data_received(g::uint /* stream */, g::uint /* component */, void * /* buffer */, size_t /* length */);

			virtual void on_local_ice_candidate(g::uint /* stream */, g::uint /* component */, g::_char* /* foundation */);
			virtual void on_gathering_done(g::uint stream_id);

			virtual void on_selected_pair(g::uint /* stream */, g::uint /* component */, NiceCandidate* /* local candidate */, NiceCandidate* /* remote candidate */);
			virtual void on_state_change(g::uint /* stream */, g::uint /* component */, g::uint /* state */);
			virtual void on_transport_writeable(g::uint /* stream */, g::uint /* component */);
		private:
			std::recursive_mutex io_lock;
			std::shared_ptr<pipes::Logger> _logger;
			std::shared_ptr<Config> config;

			std::unique_ptr<NiceAgent, void (*)(g::pointer)> agent;
			std::unique_ptr<GMainLoop, void (*)(GMainLoop*)> loop;
			bool own_loop = false;

			std::thread g_main_loop_thread;
			std::recursive_mutex streams_lock;
			std::deque<std::shared_ptr<NiceStream>> streams;

			cb_candidate callback_local_candidates;
			cb_failed callback_failed;
	};
}