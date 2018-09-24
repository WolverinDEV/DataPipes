//
// Created by wolverindev on 03.08.18.
//
#define INET
#define INET6
#include <usrsctp.h>
#include <cstring>
#include <iostream>
#include <thread>
#include <bitset>
#include <csignal>
#include "include/sctp.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace pipes;

SCTP::SCTP(uint16_t local_port) : Pipeline("SCTP"), _local_port(local_port) {
	if(!global_initialized) {
		global_initialized = true;
		usrsctp_init(0, &pipes::SCTP::cb_send, nullptr); //May not static anymore if its even possible?
		usrsctp_sysctl_set_sctp_ecn_enable(0);
	}
}

SCTP::~SCTP() {
	lock_guard<recursive_mutex> io_lock(this->io_lock);
	this->finalize();
	lock_guard<recursive_mutex> connect_lock(this->connect_lock); //Just wait for the connect step
}

int SCTP::cb_send(void *sctp_ptr, void *data, size_t len, uint8_t tos, uint8_t set_df) {
	if(!sctp_ptr) return -1;
	return ((SCTP*) sctp_ptr)->on_data_out(string((const char*) data, len));
}

int SCTP::cb_read(struct socket *sock, union sctp_sockstore addr, void *data, size_t len, struct sctp_rcvinfo recv_info, int flags, void *user_data) {
	if(!user_data) return -1;
	if(data) {
		((SCTP*) user_data)->on_data_in(string((const char*) data, len), recv_info, flags);
		free(data);
	} else {
		((SCTP*) user_data)->on_disconnect();
	}
	return 1;
}

//TODO some kind of cleanup
#define ERRORQ(message) \
do { \
	error = message; \
	return false; \
} while(0)


#define MAX_OUT_STREAM 16
#define MAX_IN_STREAM 2048
static uint16_t interested_events[] = {
		SCTP_ASSOC_CHANGE,
		SCTP_PEER_ADDR_CHANGE,
		SCTP_REMOTE_ERROR,
		SCTP_SEND_FAILED,

		SCTP_SENDER_DRY_EVENT,
		SCTP_SHUTDOWN_EVENT,
		SCTP_ADAPTATION_INDICATION,
		SCTP_PARTIAL_DELIVERY_EVENT,

		SCTP_AUTHENTICATION_EVENT,
		SCTP_STREAM_RESET_EVENT,
		SCTP_ASSOC_RESET_EVENT,
		SCTP_STREAM_CHANGE_EVENT,

		SCTP_SEND_FAILED_EVENT
};

bool SCTP::global_initialized = false;
//TODO: error callbacks
//NOTE Start learning what this magic here does?
bool SCTP::initialize(std::string &error) {
	usrsctp_register_address(this);
	sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, &SCTP::cb_read, nullptr, 0, this);
	if (!sock)
		ERRORQ("Could not create usrsctp_socket. errno=" + to_string(errno));

	struct linger linger_opt{};
	linger_opt.l_onoff = 1;
	linger_opt.l_linger = 0;
	if (usrsctp_setsockopt(this->sock, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt)) == -1)
		ERRORQ("Could not set socket options for SO_LINGER. errno=" + to_string(errno));

	struct sctp_paddrparams peer_param{};
	memset(&peer_param, 0, sizeof(peer_param));
	peer_param.spp_flags = SPP_PMTUD_DISABLE;
	peer_param.spp_pathmtu = 1200;  // XXX: Does this need to match the actual MTU?
	if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &peer_param, sizeof(peer_param)) == -1)
		ERRORQ("Could not set socket options for SCTP_PEER_ADDR_PARAMS. errno=" + to_string(errno));

	struct sctp_assoc_value av{};
	av.assoc_id = SCTP_ALL_ASSOC;
	av.assoc_value = 1;
	if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(av)) == -1)
		ERRORQ("Could not set socket options for SCTP_ENABLE_STREAM_RESET. errno=" + to_string(errno));

	uint32_t nodelay = 1;
	if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay)) == -1)
		ERRORQ("Could not set socket options for SCTP_NODELAY. errno=" + to_string(errno));

	/* Enable the events of interest */
	struct sctp_event event{};
	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	int num_events = sizeof(interested_events) / sizeof(uint16_t);
	for (int i = 0; i < num_events; i++) {
		event.se_type = interested_events[i];
		if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) == -1)
			ERRORQ("Could not set socket options for SCTP_EVENT " + to_string(i) + ". errno=" + to_string(errno));
	}

	struct sctp_initmsg init_msg{};
	memset(&init_msg, 0, sizeof(init_msg));
	init_msg.sinit_num_ostreams = MAX_OUT_STREAM;
	init_msg.sinit_max_instreams = MAX_IN_STREAM;
	if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_INITMSG, &init_msg, sizeof(init_msg)) == -1)
		ERRORQ("Could not set socket options for SCTP_INITMSG. errno=" + to_string(errno));

	struct sockaddr_conn sconn{};
	sconn.sconn_family = AF_CONN;
	sconn.sconn_port = htons(_local_port);
	sconn.sconn_addr = (void *)this;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif

	if (usrsctp_bind(this->sock, (struct sockaddr *)&sconn, sizeof(sconn)) == -1)
		ERRORQ("Could not usrsctp_bind. errno=" + to_string(errno));

	return true;
}

void SCTP::finalize() {
	if(this->sock) {
		usrsctp_shutdown(this->sock, SHUT_RDWR);
		usrsctp_close(this->sock);
		this->sock = nullptr;
	}
	usrsctp_deregister_address(this);
}

#define READ_BUFFER_SIZE 1024
ProcessResult SCTP::process_data_in() {
	lock_guard<recursive_mutex> lock(this->io_lock);
	char buffer[READ_BUFFER_SIZE];

	auto read = this->buffer_read_read_bytes(buffer, READ_BUFFER_SIZE);
	if(read > 0) usrsctp_conninput(this, buffer, read, 0);
	return ProcessResult::PROCESS_RESULT_OK;
}

ProcessResult SCTP::process_data_out() {
	lock_guard<recursive_mutex> lock(this->io_lock);
	SCTPMessage message;
	{
		lock_guard<mutex> buffer_lock(this->buffer_lock);
		if(this->write_buffer.empty()) return PROCESS_RESULT_OK;

		message = std::move(this->write_buffer[0]);
		this->write_buffer.pop_front();
	}

	struct sctp_sendv_spa spa = {0};
	memset(&spa, 0, sizeof(struct sctp_sendv_spa));
	// spa.sendv_flags = SCTP_SEND_SNDINFO_VALID | SCTP_SEND_PRINFO_VALID;

	spa.sendv_sndinfo.snd_sid = message.channel_id;
	spa.sendv_sndinfo.snd_ppid = htonl(message.ppid);

	// spa.sendv_sndinfo.snd_flags = SCTP_EOR | SCTP_UNORDERED;
	spa.sendv_sndinfo.snd_flags = SCTP_EOR; //| SCTP_UNORDERED; depends on the datachannel type
	spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;

/*
	if((channel->pr_policy == SCTP_PR_SCTP_TTL) || (channel->pr_policy == SCTP_PR_SCTP_RTX)) {
		spa.sendv_prinfo.pr_policy = channel->pr_policy;
		spa.sendv_prinfo.pr_value = channel->pr_value;
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
	}
*/
	spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
	spa.sendv_prinfo.pr_value = 0;

	auto send = usrsctp_sendv(this->sock, message.data.data(), message.data.length(), nullptr, 0, &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
	if(send < 0) {
		LOG_ERROR(this->logger(), "SCTP::process_data_out", "Failed to send data! Return code %i but expected %i", send, message.data.length());
		return ProcessResult::PROCESS_RESULT_ERROR;
	}
	return ProcessResult::PROCESS_RESULT_OK;
}

int SCTP::on_data_out(const std::string &data) {
	this->_callback_write(data);
	return 0;
}

int SCTP::on_disconnect() {
	this->finalize();
	this->_callback_error(1, "Disconnected!"); //FIXME Using callback disconnected
	return 0;
}

//TODO error handling?
int SCTP::on_data_in(const std::string &data, struct sctp_rcvinfo recv_info, int flags) {
	LOG_VERBOSE(this->_logger, "SCTP::on_data_in", "Got new data. Length: %i Flags: %s", data.length(), bitset<16>(flags).to_string().c_str());
	if((flags & MSG_NOTIFICATION) > 0) {
		auto notify = (union sctp_notification *) data.data();
		if(notify->sn_header.sn_length != data.length()) {
			LOG_DEBUG(this->_logger, "SCTP::on_data_in", "Invalid notification length (%ui != %ul)", notify->sn_header.sn_length, data.length());
			return -1;
		}
		if(this->callback_notification)
			this->callback_notification(notify);
	} else {
		if(this->_callback_data)
			this->_callback_data({data, recv_info.rcv_sid, ntohl(recv_info.rcv_ppid)});
	}
	return 1;
}

bool SCTP::connect(int32_t remote_port) {
	lock_guard<recursive_mutex> lock(this->connect_lock);

	if(remote_port > 0 && remote_port < 0xFFFF)
		this->_remote_port = static_cast<uint16_t>(remote_port);

	struct sockaddr_conn sconn{};
	sconn.sconn_family = AF_CONN;
	sconn.sconn_port = htons(_remote_port);
	sconn.sconn_addr = (void *)this;

#if defined(__APPLE__) || defined(__Bitrig__) || defined(__DragonFly__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	sconn.sconn_len = sizeof((void *)this);
#endif

	// Blocks until connection succeeds/fails
	int connect_result = usrsctp_connect(sock, (struct sockaddr *)&sconn, sizeof sconn);
	if ((connect_result < 0) && (errno != EINPROGRESS)) {
		//TODO close still?
		LOG_INFO(this->_logger, "SCTP::connect", "Result: %i (errno: %i, message: %s)", connect_result, errno, strerror(errno));
		return false;
	}
	return true;
}