//
// Created by wolverindev on 03.08.18.
//

#include <netdb.h>
#include <iostream>
#include <sstream>
#include <assert.h>
#include "include/rtc/NiceWrapper.h"

using namespace std;
using namespace rtc;

NiceWrapper::NiceWrapper(const std::shared_ptr<Config>& config) : config(config), loop(nullptr), agent(nullptr, nullptr) {}
NiceWrapper::~NiceWrapper() {}

/* Static callbacks */ //TODO Test pointers for validation!
void NiceWrapper::cb_recived(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	wrapper->on_data_recived(stream_id, component_id, buf, len);
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

//TODO some kind of cleanup!
#define ERRORQ(message) \
do { \
	error = message; \
	return false; \
} while(0)

bool NiceWrapper::initialize(std::string& error) {
	if(this->config->ice_servers.size() != 1) ERRORQ("Invalid ice server count!");

	/* log setup */
	//int log_flags = G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION;
	//g_log_set_handler(NULL, (GLogLevelFlags)log_flags, nice_log_handler, this);

	//TODO allow other loops (May via config?)
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
			//TODO log messages!
			//logger->warn("Failed to lookup host for server: {}", ice_server);
		} else {
			auto address = (in_addr *)stun_host->h_addr;
			const char *ip_address = inet_ntoa(*address);

			g_object_set(G_OBJECT(agent.get()), "stun-server", ip_address, NULL);
		}

		if (ice_server.port > 0) {
			g_object_set(G_OBJECT(agent.get()), "stun-server-port", ice_server.port, NULL);
		} else {
			//TODO log messages!
			//logger->error("stun port empty");
		}
	}

	g_signal_connect(G_OBJECT(agent.get()), "candidate-gathering-done", G_CALLBACK(NiceWrapper::cb_candidate_gathering_done), this);
	g_signal_connect(G_OBJECT(agent.get()), "component-state-changed", G_CALLBACK(NiceWrapper::cb_component_state_changed), this);
	g_signal_connect(G_OBJECT(agent.get()), "new-candidate-full", G_CALLBACK(NiceWrapper::cb_new_local_candidate), this);
	g_signal_connect(G_OBJECT(agent.get()), "new-selected-pair", G_CALLBACK(NiceWrapper::cb_new_selected_pair), this);

	//TODO allow multiple streams!
	this->stream = make_unique<NiceStream>();
	this->stream->stream_id = nice_agent_add_stream(agent.get(), 1);
	if (this->stream->stream_id == 0) {
		this->stream.reset();
		return false;
	}

	nice_agent_set_stream_name(agent.get(), this->stream_id(), "application");

	if (!config->ice_ufrag.empty() && !config->ice_pwd.empty())
		nice_agent_set_local_credentials(agent.get(), this->stream_id(), config->ice_ufrag.c_str(), config->ice_pwd.c_str());
	if (config->ice_port_range.first != 0 || config->ice_port_range.second != 0)
		nice_agent_set_port_range(agent.get(), this->stream_id(), 1, config->ice_port_range.first, config->ice_port_range.second);

	return (bool) nice_agent_attach_recv(agent.get(), this->stream_id(), 1, g_main_loop_get_context(loop.get()), NiceWrapper::cb_recived, this);
}

void NiceWrapper::finalize() {
	g_main_loop_quit(this->loop.get());

	if (this->g_main_loop_thread.joinable())
		this->g_main_loop_thread.join();
}

//TODO right log messages!
void NiceWrapper::send_data(guint stream, guint component, const std::string &data) {
	auto result = nice_agent_send(this->agent.get(), stream, component, data.length(), data.data());
	if(result != data.length()) {
		cerr << "Failed to send data! (" << result << "/" << data.length() << ")" << endl;
	}
}

void NiceWrapper::set_callback_local_candidate(const rtc::NiceWrapper::cb_candidate &cb) {
	this->callback_local_candidate = cb;
}

void NiceWrapper::set_callback_recive(const std::function<void(const std::string &)> &cb) {
	this->callback_recive = cb;
}

void NiceWrapper::set_callback_ready(const rtc::NiceWrapper::cb_ready &cb) {
	this->callback_ready = cb;
}

//TODO right log messages!
void NiceWrapper::on_data_recived(guint stream_id, guint component_id, void* data, size_t length) {
	if(this->stream_id() != stream_id) {
		cerr << "Invalid stream id!" << endl;
		return;
	}
	if(this->callback_recive)
		this->callback_recive(string((const char*) data, length));
}

//TODO right log messages!
void NiceWrapper::on_gathering_done() {
	cout << "gathering completed!" << endl;
}

//TODO right log messages!
void NiceWrapper::on_selected_pair(guint stream_id, guint component_id, NiceCandidate *, NiceCandidate *) {
	if(this->stream_id() != stream_id) {
		cerr << "Invalid stream id!" << endl;
		return;
	}
	cout << "got ice pair!" << endl;
}

//TODO right log messages!
void NiceWrapper::on_state_change(guint stream_id, guint component_id, guint state) {
	if(this->stream_id() != stream_id) {
		cerr << "Invalid stream id!" << endl;
		return;
	}

	switch (state) {
		case (NICE_COMPONENT_STATE_DISCONNECTED):
			cout << "ICE: DISCONNECTED" << endl;
			break;
		case (NICE_COMPONENT_STATE_GATHERING):
			cout << "ICE: GATHERING" << endl;
			break;
		case (NICE_COMPONENT_STATE_CONNECTING):
			cout << "ICE: CONNECTING" << endl;
			break;
		case (NICE_COMPONENT_STATE_CONNECTED):
			cout << "ICE: CONNECTED (" << component_id << ")" << endl;
			break;
		case (NICE_COMPONENT_STATE_READY):
			cout << "ICE: READY (" << component_id << ")" << endl;
			if(!this->stream->ready) {
				this->stream->ready = true;
				this->on_ice_ready();
			}
			break;
		case (NICE_COMPONENT_STATE_FAILED):
			cout << "ICE FAILED: component_id=" << component_id << endl;
			break;
		default:
			cout << "ICE: Unknown state: " << state << endl;
			break;
	}
}

void NiceWrapper::on_ice_ready() {
	if(this->callback_ready)
		this->callback_ready();
}

void NiceWrapper::on_local_ice_candidate(const std::string &candidate) { this->callback_local_candidate(candidate); }

ssize_t NiceWrapper::apply_remote_ice_candidates(const std::deque<std::string> &candidates) {
	if(candidates.empty()) return -1;
	if(nice_agent_get_component_state(this->agent.get(), this->stream_id(), 1) > NICE_COMPONENT_STATE_GATHERING) return -1; //Not disconnected or gathering

	GSList* list = nullptr;
	for (const auto& candidate_sdp : candidates) {
		auto candidate = nice_agent_parse_remote_candidate_sdp(this->agent.get(), this->stream_id(), candidate_sdp.c_str());
		if(!candidate) {
			//TODO log message?
			continue;
		}
		list = g_slist_append(list, candidate);
	}
	if(!list) return -2;

	auto result = nice_agent_set_remote_candidates(this->agent.get(), this->stream_id(), 1, list);
	g_slist_free_full(list, (GDestroyNotify)&nice_candidate_free);
	return result;
}

bool NiceWrapper::apply_remote_sdp(std::string& error, std::string sdp) {
	{ //Replace \r\n to \n
		size_t index = 0;
		while((index = sdp.find("\r\n", index)) != string::npos)
			sdp = sdp.replace(index, 2, "\n");
	}

	int rc = nice_agent_parse_remote_sdp(this->agent.get(), sdp.c_str());
	if(rc < 0) ERRORQ("Invalid return code (" + to_string(rc) + ")");

	if (!nice_agent_gather_candidates(agent.get(), this->stream_id())) ERRORQ("gather candidates failed");
	return true;
}

std::string NiceWrapper::generate_local_sdp(bool candidates) {
	std::stringstream nice_sdp;
	std::stringstream result;
	std::string line;

	auto raw_sdp = unique_ptr<gchar, decltype(g_free)*>(nice_agent_generate_local_sdp(agent.get()), ::g_free);
	assert(raw_sdp);
	nice_sdp << raw_sdp.get();

	cout << " -> " << nice_sdp.str() << endl;
	while (std::getline(nice_sdp, line)) {
		if (g_str_has_prefix(line.c_str(), "a=ice-ufrag:") || g_str_has_prefix(line.c_str(), "a=ice-pwd:") || (candidates && g_str_has_prefix(line.c_str(), "a=candidate:"))) {
			result << line << "\r\n";
		}
	}
	return result.str();
}