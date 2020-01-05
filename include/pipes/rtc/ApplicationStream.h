#pragma once

#include <map>
#include <thread>
#include "./Stream.h"
#include "pipes/tls.h"
#include "pipes/sctp.h"

namespace rtc {
	class ApplicationStream;
	class DataChannel {
			friend class ApplicationStream;
		public:
			typedef std::function<void()> cb_close;
			typedef std::function<void(const pipes::buffer_view&)> cb_text;
			typedef std::function<void(const pipes::buffer_view&)> cb_binary;

			enum MessageType {
				BINARY,
				TEXT
			};

			cb_close callback_close;
			cb_text callback_text;
			cb_binary callback_binary;

			[[nodiscard]] uint16_t id() const;
			[[nodiscard]] std::string lable() const;
			[[nodiscard]] std::string protocol() const;

            [[nodiscard]] bool readable() const { return this->read; }
            [[nodiscard]] bool writeable() const { return this->write; }

			void send(const pipes::buffer_view& /* message */, MessageType /* type */ = BINARY);
			void close();
		private:
			DataChannel(ApplicationStream*, uint16_t id, std::string lable, std::string protocol);

			bool read = true, write = true;
			ApplicationStream* owner;
			uint16_t _id;
			std::string _lable;
			std::string _protocol;
	};

	class MergedStream;
	class ApplicationStream : public Stream {
			friend class DataChannel;
			friend class PeerConnection;
			friend class MergedStream;
		public:
			struct Configuration {
				std::shared_ptr<pipes::Logger> logger;

				size_t max_data_channels = 255;
				uint16_t local_port = 5000;
			};
			typedef std::function<void(const std::shared_ptr<DataChannel>&)> cb_datachannel_new;

			ApplicationStream(PeerConnection* /* owner */, NiceStreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
			virtual ~ApplicationStream();

            [[nodiscard]] StreamType type() const override { return StreamType::CHANTYPE_APPLICATION; }

			bool initialize(std::string& /* error */) override;
			bool apply_sdp(const json& /* sdp */, const json& /* media */) override;
            [[nodiscard]] const std::string& get_mid() const override { return this->mid; }
			std::string generate_sdp() override;
			bool reset(std::string& /* error */) override;


			std::shared_ptr<DataChannel> find_datachannel(uint16_t /* channel id */);
			std::shared_ptr<DataChannel> find_datachannel(const std::string& /* channel name */);

			cb_datachannel_new callback_datachannel_new = nullptr;
		private:
		protected:
			void on_dtls_initialized(const std::shared_ptr<DTLSPipe>&certificate) override;

		private:
			void send_sctp(const pipes::SCTPMessage & /* message */);
            bool process_incoming_dtls_data(const pipes::buffer_view& /* data */) override;
            bool process_incoming_rtp_data(RTPPacket& /* data */) override;
            bool process_incoming_rtcp_data(RTCPPacket& /* data */) override;

			virtual void handle_sctp_message(const pipes::SCTPMessage& /* message */);
			virtual void handle_sctp_event(union sctp_notification * /* event */);
			void send_sctp_event(uint16_t /* channel id (useless?) */, union sctp_notification* /* event */);

			virtual void handle_datachannel_new(uint16_t /* channel id */, const pipes::buffer_view& /* data */);
			virtual void handle_datachannel_ack(uint16_t /* channel id */);

			virtual void handle_datachannel_message(uint16_t /* channel id */, uint32_t /* message type */, const pipes::buffer_view& /* message */);
			virtual void handle_event_stream_reset(struct sctp_stream_reset_event &);

			virtual void close_datachannel(DataChannel* /* channel */);

		private:
			std::shared_ptr<Configuration> config;
			std::map<uint16_t, std::shared_ptr<DataChannel>> active_channels;

			bool external_sctp_port;
			std::unique_ptr<pipes::SCTP> sctp;
	};
}