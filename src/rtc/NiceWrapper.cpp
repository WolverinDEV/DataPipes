#include <memory>

#include <netdb.h>
#include <iostream>
#include <sstream>
#include <cassert>
#include <mutex>
#include <algorithm>
#include <include/rtc/NiceWrapper.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "include/rtc/NiceWrapper.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace rtc;

void _null_deleter(GMainLoop* loop) { }

NiceWrapper::NiceWrapper(const std::shared_ptr<Config>& config) : config(config), agent(nullptr, nullptr), loop(nullptr, _null_deleter) {}
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
	wrapper->on_gathering_done(stream_id);
}

void NiceWrapper::cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	wrapper->on_state_change(stream_id, component_id, state);
}

void NiceWrapper::cb_new_local_candidate(NiceAgent *agent, guint stream_id, guint component_id, gchar* foundation, gpointer user_data) {
	auto wrapper = static_cast<NiceWrapper*>(user_data);
	wrapper->on_local_ice_candidate(stream_id, component_id, foundation);
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
	g_log_set_handler(nullptr, (GLogLevelFlags) log_flags, g_log_handler, this);

	if(this->config->main_loop) {
		this->loop = std::unique_ptr<GMainLoop, void(*)(GMainLoop*)>(&*this->config->main_loop, _null_deleter);//std::unique_ptr<GMainLoop, void(*)(GMainLoop*)>(g_main_loop_ref(&*this->config->main_loop), g_main_loop_unref);
		if(!this->loop)
			ERRORQ("Failed to reference the main loop");
		this->own_loop = false;
	} else {
		this->loop = std::unique_ptr<GMainLoop, void(*)(GMainLoop*)>(g_main_loop_new(nullptr, false), g_main_loop_unref);
		this->own_loop = true;
		this->g_main_loop_thread = std::thread(g_main_loop_run, this->loop.get());
	}
	if (!this->loop) ERRORQ("Failed to initialize GMainLoop");

	this->agent = std::unique_ptr<NiceAgent, decltype(&g_object_unref)>(nice_agent_new(g_main_loop_get_context(loop.get()), NICE_COMPATIBILITY_RFC5245), g_object_unref);
	if (!this->agent) ERRORQ("Failed to initialize nice agent");


	g_object_set(G_OBJECT(agent.get()), "upnp", false, nullptr);
	g_object_set(G_OBJECT(agent.get()), "controlling-mode", 0, NULL);

	struct addrinfo hints{}, *info_ptr = nullptr;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; //IPv4 only

	char address_buffer[256];

	for (const auto& ice_server : config->ice_servers) {
		if (ice_server.port <= 0) {
			LOG_ERROR(this->_logger, "NiceWrapper::initialize", "Invalid stun port! (%i)", ice_server.port);
			continue;
		}

		int state = getaddrinfo(ice_server.host.c_str(), nullptr, &hints, &info_ptr);
		if(state) {
			LOG_ERROR(this->_logger, "NiceWrapper::initialize", "Failed to lookup host for ice server %s:%i (State: %i)", ice_server.host.c_str(), ice_server.port, state);
			continue;
		}

		struct addrinfo *address;
		for (address = info_ptr; address != nullptr; address = address->ai_next) {
			if(getnameinfo(address->ai_addr, address->ai_addrlen, address_buffer, sizeof(address_buffer), nullptr, 0, NI_NUMERICHOST)> 0)
				continue;

			g_object_set(G_OBJECT(agent.get()), "stun-server", address_buffer, NULL);
			LOG_DEBUG(this->_logger, "NiceWrapper::initialize", "Set stun server to %s:%i, resolved from hostname %s", address_buffer, ice_server.port, ice_server.host.c_str());
			break;
		}
		freeaddrinfo(info_ptr);
		info_ptr = nullptr;

		g_object_set(G_OBJECT(agent.get()), "stun-server-port", ice_server.port, NULL);
		break; /* only one server */
	}

	g_signal_connect(G_OBJECT(agent.get()), "candidate-gathering-done", G_CALLBACK(NiceWrapper::cb_candidate_gathering_done), this);
	g_signal_connect(G_OBJECT(agent.get()), "component-state-changed", G_CALLBACK(NiceWrapper::cb_component_state_changed), this);
	g_signal_connect(G_OBJECT(agent.get()), "new-candidate", G_CALLBACK(NiceWrapper::cb_new_local_candidate), this);
	g_signal_connect(G_OBJECT(agent.get()), "new-selected-pair", G_CALLBACK(NiceWrapper::cb_new_selected_pair), this);
	g_signal_connect(G_OBJECT(agent.get()), "reliable-transport-writable", G_CALLBACK(NiceWrapper::cb_transport_writeable), this);

	/* Add all local addresses, except those in the ignore list */
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;
	char host[NI_MAXHOST];
	if(getifaddrs(&ifaddr) == -1) {
		LOG_ERROR(this->_logger, "NiceWrapper::initialize", "Failed to getting a list of interfaces for local turn server...");
	} else {
		for(ifa = ifaddr, n = 0; ifa != nullptr; ifa = ifa->ifa_next, n++) {
			if(ifa->ifa_addr == nullptr)
				continue;
			/* Skip interfaces which are not up and running */
			if (!((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)))
				continue;
			/* Skip loopback interfaces */
			if (ifa->ifa_flags & IFF_LOOPBACK)
				continue;
			family = ifa->ifa_addr->sa_family;
			if(family != AF_INET && family != AF_INET6)
				continue;
			/* We only add IPv6 addresses if support for them has been explicitly enabled (still WIP, mostly) */
			if(family == AF_INET6) //FIXME!
				continue;
			/* Check the interface name first, we can ignore that as well: enforce list would be checked later */
			//if(janus_ice_enforce_list == NULL && ifa->ifa_name != NULL && janus_ice_is_ignored(ifa->ifa_name))
			//	continue;
			s = getnameinfo(ifa->ifa_addr,
			                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
			                host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
			if(s != 0) {
				LOG_ERROR(this->_logger, "NiceWrapper::initialize", "getnameinfo() failed: %s", gai_strerror(s));
				continue;
			}
			/* Skip 0.0.0.0, :: and local scoped addresses  */
			if(!strcmp(host, "0.0.0.0") || !strcmp(host, "::") || !strncmp(host, "fe80:", 5))
				continue;
			/* Check if this IP address is in the ignore/enforce list, now: the enforce list has the precedence */

			/* Ok, add interface to the ICE agent */
			LOG_ERROR(this->_logger, "NiceWrapper::initialize", "Adding %s to the addresses to gather candidates for", host);
			NiceAddress addr_local;
			nice_address_init (&addr_local);
			if(!nice_address_set_from_string (&addr_local, host)) {
				LOG_ERROR(this->_logger, "NiceWrapper::initialize", "Skipping invalid address %s", host);
				continue;
			}
			nice_agent_add_local_address (this->agent.get(), &addr_local);
		}
		freeifaddrs(ifaddr);
	}
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

	if(this->loop && this->agent) { //Finish handling
		auto context = g_main_loop_get_context(loop.get());
		if(!g_main_context_ref(context)) {
			//TODO error
		}

		for(const auto& stream : this->available_streams()) {
			nice_agent_attach_recv(agent.get(), stream->stream_id, 1, context, nullptr, nullptr);
			nice_agent_remove_stream(agent.get(), stream->stream_id);
		}
		{ //Let the other thread so something with IO
			lock.unlock();
			size_t iterations = 0, max_iterations = 1024;
			while(g_main_context_iteration(context, false) && iterations < max_iterations) { } /* flush */
			if(max_iterations == iterations); //TODO error?
			lock.lock();
		}
		g_main_context_unref(context);
		this->streams.clear();
	}
	{ /* allow the agent to remove all events from the event loop, may event triggers some events then */
		lock.unlock();
		this->agent.reset();
		lock.lock();
	}

	if(this->own_loop && this->loop) {
		g_main_loop_quit(this->loop.get());

		if (this->g_main_loop_thread.joinable())
			this->g_main_loop_thread.join();
	}
	this->loop.reset();
}

bool NiceWrapper::send_data(guint stream, guint component, const pipes::buffer_view &data) {
	if(!this->agent.get()) return false;
	//LOG_DEBUG(this->_logger, "NiceWrapper::send_data", "Sending on stream %i component %i", stream, component);

	auto result = nice_agent_send(this->agent.get(), stream, component, data.length(), (gchar*) data.data_ptr());
	if(result < 0 || (size_t) result != data.length()) {
		LOG_ERROR(this->_logger, "NiceWrapper::send_data", "Failed to send data to agent! (Expected length: %i Recived length: %i)", data.length(), result);
		return false;
	}
	return true;
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
		stream->callback_receive(pipes::buffer_view{data, length});
}

void NiceWrapper::on_gathering_done(guint stream_id) {
	LOG_DEBUG(this->_logger, "NiceWrapper::on_gathering_done", "Gathering completed for stream %u", stream_id);
}

void NiceWrapper::on_selected_pair(guint stream_id, guint component_id, NiceCandidate *local, NiceCandidate *remote) {
	auto stream = this->find_stream(stream_id);
	if(!stream) {
		LOG_ERROR(this->_logger, "NiceWrapper::on_selected_pair", "Missing stream %i", stream_id);
		return;
	}

	/* Dosn't work that well
	auto local_string = unique_ptr<gchar, decltype(g_free)*>(nice_agent_generate_local_candidate_sdp(this->agent.get(), local), ::g_free);
	auto remote_string = unique_ptr<gchar, decltype(g_free)*>(nice_agent_generate_local_candidate_sdp(this->agent.get(), remote), ::g_free);
	LOG_DEBUG(this->_logger, "NiceWrapper::on_selected_pair", "Gathered ICE pair for %u (%u): local=%s, remote=%s", stream_id, component_id, local_string.get(), remote_string.get());
	 */
}

void NiceWrapper::on_transport_writeable(guint stream_id, guint component) {
	auto stream = this->find_stream(stream_id);
	if(!stream) {
		LOG_ERROR(this->_logger, "NiceWrapper::on_transport_writeable", "Missing stream %i", stream_id);
		return;
	}
	LOG_DEBUG(this->_logger, "NiceWrapper::on_transport_writeable", "Stream %u (%u) is writeable again", stream_id, component);
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
				this->callback_failed(stream);
			break;
		default:
			LOG_INFO(this->_logger, "NiceWrapper::on_state_change", "Received new unknown state for stream %i (%u). State: %i", stream_id, component_id, state);
			break;
	}
}

void candidate_list_free(GSList* list) {
	g_slist_free_full(list, (GDestroyNotify) &nice_candidate_free);
}

void NiceWrapper::on_local_ice_candidate(guint stream_id, guint component_id, gchar *foundation) {
	auto stream = this->find_stream(stream_id);
	if(!stream) {
		LOG_ERROR(this->_logger, "NiceWrapper::on_local_ice_candidate", "Missing stream %i (%i)", stream_id, component_id);
		return;
	}

	auto candidates = unique_ptr<GSList, decltype(&candidate_list_free)>(nice_agent_get_local_candidates(this->agent.get(), stream_id, component_id), &candidate_list_free);

	NiceCandidate* candidate = nullptr;
	GSList* index = &*candidates;

	while(index) {
		auto can = (NiceCandidate *) index->data;
		if(!strcasecmp(can->foundation, foundation)) { //Search for the candidate
			candidate = can;
			break;
		}
		index = index->next;
	}
	if(!candidate) {
		LOG_ERROR(this->_logger, "NiceWrapper::on_local_ice_candidate", "Got local candidate without handle! (Foundation %s)", foundation);
		return;
	}

	auto candidate_string = unique_ptr<gchar, decltype(g_free)*>(nice_agent_generate_local_candidate_sdp(this->agent.get(), candidate), ::g_free);
	if(this->callback_local_candidate)
		this->callback_local_candidate(stream, string(candidate_string.get()));
}


ssize_t NiceWrapper::apply_remote_ice_candidates(const std::shared_ptr<rtc::NiceStream> &stream, const std::deque<std::string> &candidates) {
	std::lock_guard<std::recursive_mutex> lock(io_lock);

	if(candidates.empty()) return -1;
	//if(nice_agent_get_component_state(this->agent.get(), this->stream_id(), 1) > NICE_COMPONENT_STATE_CONNECTING) return -1; //Not disconnected or gathering

	GSList* list = nullptr; //nice_agent_get_remote_candidates(this->agent.get(), stream->stream_id, 1);
	for (const auto& candidate_sdp : candidates) {
		auto candidate = nice_agent_parse_remote_candidate_sdp(this->agent.get(), stream->stream_id, candidate_sdp.c_str());
		if(!candidate) {
			LOG_ERROR(this->_logger, "NiceWrapper::apply_remote_ice_candidates", "Failed to parse candidate. Ignoring it! Candidate: %s", candidate_sdp.c_str());
			continue;
		}
		list = g_slist_append(list, candidate);
	}
	if(!list) return -2;

	LOG_VERBOSE(this->_logger, "NiceWrapper::apply_remote_ice_candidates", "Setting remote candidates for %u", stream->stream_id);
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

	auto raw_sdp = unique_ptr<gchar, decltype(g_free)*>(nice_agent_generate_local_sdp(agent.get()), ::g_free); //TODO may use nice_agent_generate_local_stream_sdp?
	assert(raw_sdp);
	nice_sdp << raw_sdp.get();

	std::unique_ptr<LocalSdpEntry> current;
	while (std::getline(nice_sdp, line)) {
		if(g_str_has_prefix(line.c_str(), "m=")) {
			if(current)
				result.push_back(std::move(current));
			current = std::make_unique<LocalSdpEntry>();
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
			} else if(g_str_has_prefix(line.c_str(), "a=candidate:")) {
				if(candidates) {
					current->candidates.push_back(line.substr(line.find(':') + 1)); //Example: a=candidate:25 1 UDP 2013266431 fe80::f822:34ff:febd:6c7a 37691 typ host
					current->has.candidates = true;
				}
			} else {
				LOG_DEBUG(this->_logger, "NiceWrapper::generate_local_sdp", "Received unknown sdp line: %s", line.c_str());
			}
		}
	}
	if(current)
		result.push_back(std::move(current));
	return result;
}