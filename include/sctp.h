#pragma once

#include <usrsctp.h>
#include "pipeline.h"

namespace pipes {
	struct SCTPMessage {
		buffer_view data;
		uint16_t channel_id;
		uint32_t ppid;
	};
	class SCTP : public Pipeline<SCTPMessage> {
		public:
			typedef std::function<void(union sctp_notification*)> cb_notification;

			explicit SCTP(uint16_t local_port);
			virtual ~SCTP();

			bool initialize(std::string& error);
			void finalize();

			bool connect(int32_t remote_port = -1);

			cb_notification callback_notification;

			uint16_t local_port() { return this->_local_port; }
			uint16_t remote_port() { return this->_remote_port; }
			void remote_port(uint16_t port) { this->_remote_port = port; } //Works only when its not already connected
		protected:
			ProcessResult process_data_in() override;
			ProcessResult process_data_out() override;

			virtual int on_data_out(const buffer_view& /* data */);
			virtual int on_data_in(const buffer_view& /* data */, struct sctp_rcvinfo recv_info, int flags);
			virtual int on_disconnect();
		private:
			std::recursive_mutex io_lock;
			std::recursive_mutex connect_lock;

			static bool global_initialized;
			static int cb_send(void *sctp_ptr, void *data, size_t len, uint8_t tos, uint8_t set_df);
			static int cb_read(struct socket *sock, union sctp_sockstore addr, void *data, size_t len, struct sctp_rcvinfo recv_info, int flags, void *user_data);

			uint16_t _local_port;
			uint16_t _remote_port = 0;

			struct socket *sock;
			int stream_cursor;
	};
}