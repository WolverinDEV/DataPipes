#include <netdb.h>
#include <iostream>
#include <sstream>
#include <cassert>
#include <mutex>
#include <algorithm>
#include <include/rtc/NiceWrapper.h>
#include "include/rtc/NiceWrapper.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace rtc;

NiceWrapper::NiceWrapper(const std::shared_ptr<Config>& config) : config(config), agent(nullptr, nullptr), loop(nullptr) {}
NiceWrapper::~NiceWrapper() {
	this->finalize();
}

/* Static callbacks */ //TODO Test pointers for validation!
void NiceWrapper::cb_received(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	wrapper->on_data_received(stream_id, component_id, buf, len);
}

void NiceWrapper::cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	wrapper->on_gathering_done();
}

void NiceWrapper::cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	wrapper->on_state_change(stream_id, component_id, state);
}

void NiceWrapper::cb_new_local_candidate(NiceAgent *agent, NiceCandidate *candidate, gpointer user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	auto candidate_string = unique_ptr<gchar, decltype(g_free)*>(nice_agent_generate_local_candidate_sdp(agent, candidate), ::g_free);
	wrapper->on_local_ice_candidate(candidate_string.get());
}

void NiceWrapper::cb_new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *lcandidate, NiceCandidate *rcandidate, gpointer user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	wrapper->on_selected_pair(stream_id, component_id, lcandidate, rcandidate);
}

void NiceWrapper::cb_transport_writeable(NiceAgent *agent, guint sid, guint cid, gpointer user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	wrapper->on_transport_writeable(sid, cid);
}

//TODO some kind of cleanup!
#define ERRORQ(message) \
do { \
	error = message; \
	return false; \
} while(0)

void g_log_handler(const gchar   *log_domain,
                   GLogLevelFlags log_level,
                   const gchar   *message,
                   gpointer       user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	LOG_VERBOSE(wrapper->logger(), "Nice::logger", message);
}

bool NiceWrapper::initialize(std::string& error) {
	//if(this->config->ice_servers.size() != 1) ERRORQ("Invalid ice server count!");

	/* log setup */
	int log_flags = G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION;
	g_log_set_handler(NULL, (GLogLevelFlags) log_flags, g_log_handler, this);

	if(this->config->main_loop) {
		this->loop = this->config->main_loop;
		this->own_loop = false;
	} else {
		this->loop = std::shared_ptr<GMainLoop>(g_main_loop_new(nullptr, false), g_main_loop_unref);
		this->own_loop = true;
		this->g_main_loop_thread = std::thread(g_main_loop_run, this->loop.get());
	}
	if (!this->loop) ERRORQ("Failed to initialize GMainLoop");

	this->agent = std::unique_ptr<NiceAgent, decltype(&g_object_unref)>(nice_agent_new(g_main_loop_get_context(loop.get()), NICE_COMPATIBILITY_RFC5245), g_object_unref);
	if (!this->agent) ERRORQ("Failed to initialize nice agent");


	g_object_set(G_OBJECT(agent.get()), "upnp", false, nullptr);
	g_object_set(G_OBJECT(agent.get()), "controlling-mode", 0, NULL);


	for (const auto& ice_server : config->ice_servers) {
		struct hostent *stun_host = gethostbyname(ice_server.host.c_str());
		if (stun_host == nullptr) {
			LOG_ERROR(this->_logger, "NiceWrapper::initialize", "Failed to lookup host for ice server %s:%i", ice_server.host, ice_server.port);
		} else {
			auto address = (in_addr *)stun_host->h_addr;
			const char *ip_address = inet_ntoa(*address);

			g_object_set(G_OBJECT(agent.get()), "stun-server", ip_address, NULL);
		}

		if (ice_server.port > 0) {
			g_object_set(G_OBJECT(agent.get()), "stun-server-port", ice_server.port, NULL);
		} else {
			LOG_ERROR(this->_logger, "NiceWrapper::initialize", "Invalid stun port! (%i)", ice_server.port);
		}
	}

	g_signal_connect(G_OBJECT(agent.get()), "candidate-gathering-done", G_CALLBACK(NiceWrapper::cb_candidate_gathering_done), this);
	g_signal_connect(G_OBJECT(agent.get()), "component-state-changed", G_CALLBACK(NiceWrapper::cb_component_state_changed), this);
	g_signal_connect(G_OBJECT(agent.get()), "new-candidate-full", G_CALLBACK(NiceWrapper::cb_new_local_candidate), this);
	g_signal_connect(G_OBJECT(agent.get()), "new-selected-pair", G_CALLBACK(NiceWrapper::cb_new_selected_pair), this);
	g_signal_connect(G_OBJECT(agent.get()), "reliable-transport-writable", G_CALLBACK(NiceWrapper::cb_transport_writeable), this);
	// signal

	return true;
}

std::shared_ptr<NiceStream> NiceWrapper::add_stream(const string& name) { //TODO individual stream passwd
	auto stream = make_shared<NiceStream>();
	stream->stream_id = nice_agent_add_stream(agent.get(), 1);
	if (stream->stream_id == 0) return nullptr;

	nice_agent_set_stream_name(agent.get(), stream->stream_id, name.c_str()); //Only valid names (Sets the stream type (unique?)): "audio", "video", "text", "application", "image" and "message"

	if (!config->ice_ufrag.empty() && !config->ice_pwd.empty())
		nice_agent_set_local_credentials(agent.get(), stream->stream_id, config->ice_ufrag.c_str(), config->ice_pwd.c_str());
	if (config->ice_port_range.first != 0 || config->ice_port_range.second != 0)
		nice_agent_set_port_range(agent.get(), stream->stream_id, 1, config->ice_port_range.first, config->ice_port_range.second);


	{
		lock_guard<recursive_mutex> lock(this->streams_lock);
		this->streams.push_back(stream);
	}
	if(!nice_agent_attach_recv(agent.get(), stream->stream_id, 1, g_main_loop_get_context(loop.get()), NiceWrapper::cb_received, this)) {
		lock_guard<recursive_mutex> lock(this->streams_lock);
		this->streams.erase(find(this->streams.begin(), this->streams.end(), stream));
		return nullptr;
	}

	return stream;
}

std::deque<std::shared_ptr<NiceStream>> NiceWrapper::available_streams() {
	lock_guard<recursive_mutex> lock(this->streams_lock);
	return this->streams;
}

std::shared_ptr<NiceStream> NiceWrapper::find_stream(rtc::StreamId id) {
	lock_guard<recursive_mutex> lock(this->streams_lock);
	for(const auto& stream : this->streams)
		if(stream->stream_id == id) return stream;
	return nullptr;
}

void NiceWrapper::finalize() {
	std::unique_lock<std::recursive_mutex> lock(io_lock);

	{
		for(const auto& stream : this->available_streams()) {
			auto context = g_main_loop_get_context(loop.get());
			if(!g_main_context_ref(context)) {
				//TODO error
			}

			nice_agent_attach_recv(agent.get(), stream->stream_id, 1, context, nullptr, nullptr);
			{ //Let the other thread so something with IO
				lock.unlock();
				if(!g_main_context_iteration(context, false)) {
					//TODO log error (cant flush ip!)
				}
				lock.lock();
			}
			g_main_context_unref(context);
		}
		this->streams.clear();
	}

	if(this->own_loop && this->loop) {
		g_main_loop_quit(this->loop.get());

		if (this->g_main_loop_thread.joinable())
			this->g_main_loop_thread.join();

		this->loop.reset();
	}

	this->agent.reset();
}

void NiceWrapper::send_data(guint stream, guint component, const std::string &data) {
	//LOG_DEBUG(this->_logger, "NiceWrapper::send_data", "Sending on stream %i component %i", stream, component);

	auto result = nice_agent_send(this->agent.get(), stream, component, data.length(), data.data());
	if(result < 0 || (size_t) result != data.length())
		LOG_ERROR(this->_logger, "NiceWrapper::send_data", "Failed to send data to agent! (Expected length: %i Recived length: %i)", data.length(), result);
}

void NiceWrapper::set_callback_local_candidate(const rtc::NiceWrapper::cb_candidate &cb) {
	this->callback_local_candidate = cb;
}

void NiceWrapper::set_callback_failed(const rtc::NiceWrapper::cb_failed &cb) {
	this->callback_failed = cb;
}

void NiceWrapper::on_data_received(guint stream_id, guint component_id, void *data, size_t length) {
	std::lock_guard<std::recursive_mutex> lock(io_lock);

	auto stream = this->find_stream(stream_id);
	if(!stream) {
		LOG_ERROR(this->_logger, "NiceWrapper::on_data_received", "Missing stream %i", stream_id);
		return;
	}
	if(stream->callback_receive)
		stream->callback_receive(string((const char*) data, length));
}

void NiceWrapper::on_gathering_done() {
	LOG_DEBUG(this->_logger, "NiceWrapper::on_gathering_done", "Gathering completed!");
}

void NiceWrapper::on_selected_pair(guint stream_id, guint component_id, NiceCandidate *, NiceCandidate *) {
	auto stream = this->find_stream(stream_id);
	if(!stream) {
		LOG_ERROR(this->_logger, "NiceWrapper::on_selected_pair", "Missing stream %i", stream_id);
		return;
	}
	LOG_DEBUG(this->_logger, "NiceWrapper::on_selected_pair", "Got ICE pair!");
}

void NiceWrapper::on_transport_writeable(guint stream_id, guint component) {
	auto stream = this->find_stream(stream_id);
	if(!stream) {
		LOG_ERROR(this->_logger, "NiceWrapper::on_transport_writeable", "Missing stream %i", stream_id);
		return;
	}
	LOG_DEBUG(this->_logger, "NiceWrapper::on_transport_writeable", "We can write again?");
}

void NiceWrapper::on_state_change(guint stream_id, guint component_id, guint state) {
	auto stream = this->find_stream(stream_id);
	if(!stream) {
		LOG_ERROR(this->_logger, "NiceWrapper::on_state_change", "Missing stream %i (%i)", stream_id, component_id);
		return;
	}

	switch (state) {
		case (NICE_COMPONENT_STATE_DISCONNECTED):
			LOG_INFO(this->_logger, "NiceWrapper::on_state_change", "Received new state for stream %i (%u). State: %s", stream_id, component_id, "DISCONNECTED");
			break;
		case (NICE_COMPONENT_STATE_GATHERING):
			LOG_INFO(this->_logger, "NiceWrapper::on_state_change", "Received new state for stream %i (%u). State: %s", stream_id, component_id, "GATHERING");
			break;
		case (NICE_COMPONENT_STATE_CONNECTING):
			LOG_INFO(this->_logger, "NiceWrapper::on_state_change", "Received new state for stream %i (%u). State: %s", stream_id, component_id, "CONNECTING");
			break;
		case (NICE_COMPONENT_STATE_CONNECTED):
			LOG_INFO(this->_logger, "NiceWrapper::on_state_change", "Received new state for stream %i (%u). State: %s", stream_id, component_id, "CONNECTED");
			break;
		case (NICE_COMPONENT_STATE_READY):
			LOG_INFO(this->_logger, "NiceWrapper::on_state_change", "Received new state for stream %i (%u). State: %s", stream_id, component_id, "READY");
			if(!stream->ready) {
				stream->ready = true;
				stream->callback_ready();
			}
			break;
		case (NICE_COMPONENT_STATE_FAILED):
			LOG_INFO(this->_logger, "NiceWrapper::on_state_change", "Received new state for stream %i. State: %s Component: %i", stream_id, "FAILED", component_id);
			if(this->callback_failed)
				this->callback_failed();
			break;
		default:
			LOG_INFO(this->_logger, "NiceWrapper::on_state_change", "Received new unknown state for stream %i (%u). State: %i", stream_id, component_id, state);
			break;
	}
}

void NiceWrapper::on_local_ice_candidate(const std::string &candidate) {
	for(const auto& stream : this->available_streams())
		this->callback_local_candidate(stream, candidate);
}

ssize_t NiceWrapper::apply_remote_ice_candidates(const std::shared_ptr<rtc::NiceStream> &stream, const std::deque<std::string> &candidates) {
	std::lock_guard<std::recursive_mutex> lock(io_lock);

	if(candidates.empty()) return -1;
	//if(nice_agent_get_component_state(this->agent.get(), this->stream_id(), 1) > NICE_COMPONENT_STATE_CONNECTING) return -1; //Not disconnected or gathering

	GSList* list = nullptr;
	for (const auto& candidate_sdp : candidates) {
		auto candidate = nice_agent_parse_remote_candidate_sdp(this->agent.get(), stream->stream_id, candidate_sdp.c_str());
		if(!candidate) {
			LOG_ERROR(this->_logger, "NiceWrapper::apply_remote_ice_candidates", "Failed to parse candidate. Ignoring it! Candidate: %s", candidate_sdp.c_str());
			continue;
		}
		list = g_slist_append(list, candidate);
	}
	if(!list) return -2;

	auto result = nice_agent_set_remote_candidates(this->agent.get(), stream->stream_id, 1, list);
	g_slist_free_full(list, (GDestroyNotify)&nice_candidate_free);
	return result;
}

bool NiceWrapper::apply_remote_sdp(std::string& error, std::string sdp) {
	std::lock_guard<std::recursive_mutex> lock(io_lock);

	{ //Replace \r\n to \n
		size_t index = 0;
		while((index = sdp.find("\r\n", index)) != string::npos)
			sdp = sdp.replace(index, 2, "\n");
	}

	int rc = nice_agent_parse_remote_sdp(this->agent.get(), sdp.c_str());
	if(rc < 0) ERRORQ("Invalid return code (" + to_string(rc) + ")");

	return true;
}

bool NiceWrapper::gather_candidates(const std::shared_ptr<rtc::NiceStream> &stream) {
	if (!nice_agent_gather_candidates(agent.get(), stream->stream_id)) return false;
	return true;
}

std::deque<std::unique_ptr<LocalSdpEntry>> NiceWrapper::generate_local_sdp(bool candidates) {
	std::lock_guard<std::recursive_mutex> lock(io_lock);

	std::stringstream nice_sdp;
	std::deque<std::unique_ptr<LocalSdpEntry>> result;
	std::string line;

	auto raw_sdp = unique_ptr<gchar, decltype(g_free)*>(nice_agent_generate_local_sdp(agent.get()), ::g_free);
	assert(raw_sdp);
	nice_sdp << raw_sdp.get();

	cout << " -> " << nice_sdp.str() << endl;

	std::unique_ptr<LocalSdpEntry> current;
	while (std::getline(nice_sdp, line)) {
		if(g_str_has_prefix(line.c_str(), "m=")) {
			if(current)
				result.push_back(std::move(current));
			current.reset(new LocalSdpEntry());
			current->index = (int) result.size();
			current->has_bitset = 0;

			current->media = line.substr(2, line.find(' ', 2) - 2);
			current->has.media = true;
		} else {
			if(!current || !current->has.media) {
				LOG_ERROR(this->_logger, "NiceWrapper::generate_local_sdp", "SDP unexpected line! Expected m=, but got: %s", line.c_str());
				continue;
			} else if(g_str_has_prefix(line.c_str(), "a=ice-ufrag:")) {
				current->ice_ufrag = line.substr(line.find(':') + 1); //Example: a=ice-ufrag:N7KM
				current->has.ice_ufrag = true;
			} else if(g_str_has_prefix(line.c_str(), "c=")) {
				current->ice_pwd = line.substr(2); //Example: c=IN IP4 172.17.0.1
				current->has.ice_pwd = true;
			} else if(g_str_has_prefix(line.c_str(), "a=ice-pwd:")) {
				current->ice_pwd = line.substr(line.find(':') + 1); //Example: a=ice-pwd:eken6xuGApU2mHxEz9FIH3
				current->has.ice_pwd = true;
			} else if(candidates && g_str_has_prefix(line.c_str(), "a=candidate:")) {
				current->candidates.push_back(line.substr(line.find(':') + 1)); //Example: a=candidate:25 1 UDP 2013266431 fe80::f822:34ff:febd:6c7a 37691 typ host
				current->has.candidates = true;
			} else {
				LOG_DEBUG(this->_logger, "NiceWrapper::generate_local_sdp", "Received unknown sdp line: %s", line.c_str());
			}
		}
	}
	if(current)
		result.push_back(std::move(current));
	return result;
}