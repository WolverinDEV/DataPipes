#pragma once

#include <usrsctp.h>
#include "pipeline.h"

namespace pipes {
	struct SCTPMessage {
		std::string data;
		uint16_t channel_id;
		uint32_t ppid;
	};
	class SCTP : public Pipeline<SCTPMessage> {
		public:
			typedef std::function<void(union sctp_notification*)> cb_notification;

			SCTP(uint16_t local_port, uint16_t remote_port);
			virtual ~SCTP();

			bool initialize(std::string& error);

			bool connect();

			cb_notification callback_notification;
		protected:
			ProcessResult process_data_in() override;
			ProcessResult process_data_out() override;

			virtual int on_data_out(const std::string& /* data */);
			virtual int on_data_in(const std::string& /* data */, struct sctp_rcvinfo recv_info, int flags);
		private:
			static bool global_initialized;
			static int cb_send(void *sctp_ptr, void *data, size_t len, uint8_t tos, uint8_t set_df);
			static int cb_read(struct socket *sock, union sctp_sockstore addr, void *data, size_t len, struct sctp_rcvinfo recv_info, int flags, void *user_data);

			uint16_t local_port;
			uint16_t remote_port;

			struct socket *sock;
			int stream_cursor;
	};
}