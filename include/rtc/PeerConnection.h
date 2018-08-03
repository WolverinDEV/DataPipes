#pragma once

#include <map>
#include <memory>
#include <include/sctp.h>
#include "NiceWrapper.h"
#include "dtls.h"

namespace rtc {
	class PeerConnection;
	class DataChannel {
		friend class PeerConnection;
		public:
			typedef std::function<void()> cb_close;
			typedef std::function<void(const std::string&)> cb_text;
			typedef std::function<void(const std::string&)> cb_binary;

			enum MessageType {
				BINARY,
				TEXT
			};

			cb_close callback_close;
			cb_text callback_text;
			cb_binary callback_binary;

			uint16_t id() const;
			std::string lable() const;
			std::string protocol() const;

			bool readable() const { return this->read; }
			bool writeable() const { return this->write; }

			void send(const std::string& /* message */, MessageType /* type */ = BINARY);
		private:
			DataChannel(PeerConnection*, uint16_t id, std::string lable, std::string protocol);

			bool read = true, write = true;
			PeerConnection* owner;
			uint16_t _id;
			std::string _lable;
			std::string _protocol;
	};

	class PeerConnection {
		public:
			struct Config {
				std::shared_ptr<NiceWrapper::Config> nice_config;

				size_t max_data_channels = 1024;
			};

			typedef std::function<void(const std::shared_ptr<DataChannel>&)> cb_datachannel_new;

			PeerConnection(const std::shared_ptr<Config>& config);
			virtual ~PeerConnection();

			std::shared_ptr<Config> configuration() { return this->config; }
			bool initialize(std::string& /* error */);

			//TODO vice versa (we create a offer and parse the answer?)
			bool apply_offer(std::string& /* error */, const std::string& /* offer */);
			int apply_ice_candidates(const std::deque<std::string>& /* candidates */);

			std::string generate_answer(bool /* candidates */);

			guint getStreamId() { return 1; }

			std::shared_ptr<DataChannel> find_datachannel(uint16_t /* channel id */);
			std::shared_ptr<DataChannel> find_datachannel(const std::string& /* channel name */);

			cb_datachannel_new callback_datachannel_new;

			void sendSctpMessage(const pipes::SCTPMessage& /* message */);
		protected:
			virtual void on_nice_ready();

			virtual void handle_sctp_message(const pipes::SCTPMessage& /* message */);
			virtual void handle_sctp_event(union sctp_notification * /* event */);
			void send_sctp_event(union sctp_notification* /* event */);

			virtual void handle_datachannel_new(uint16_t /* channel id */, const std::string& /* data */);
			virtual void handle_datachannel_ack(uint16_t /* channel id */);

			virtual void handle_datachannel_message(uint16_t /* channel id */, uint32_t /* message type */, const std::string& /* message */);
			virtual void handle_event_stream_reset(struct sctp_stream_reset_event &);
		private:
			std::shared_ptr<Config> config;

			std::unique_ptr<NiceWrapper> nice;
			std::unique_ptr<DTLS> dtls;
			std::unique_ptr<pipes::SCTP> sctp;

			std::map<uint16_t, std::shared_ptr<DataChannel>> active_channels;

			std::string mid;
			enum Role { Client, Server } role = Client;
	};
}