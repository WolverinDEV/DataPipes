#pragma once

#include <map>
#include <thread>
#include "Stream.h"

namespace rtc {
	class MergedStream : public Stream {
			friend class PeerConnection;
		public:
			struct Configuration {
				std::shared_ptr<pipes::Logger> logger;
			};

			MergedStream(PeerConnection* /* owner */, StreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
			virtual ~MergedStream();

			bool initialize(std::string& /* error */);
			bool reset(std::string& /* error */);

			bool apply_sdp(const nlohmann::json& /* sdp */, const nlohmann::json& /* media */) override;

			std::string generate_sdp() override;
			const std::string &get_mid() const override;
			StreamType type() const override;

			std::string generate_local_fingerprint();

			void send_data_dtls(const std::string& /* data */);
		private:
		protected:
			void on_nice_ready() override;
			void on_dtls_initialized(const std::unique_ptr<pipes::TLS>& /* handle */) override;
		private:
			void process_incoming_data(const std::string& /* data */);
		private:
			std::shared_ptr<Configuration> config;
			enum Role { Client, Server } role = Client;

			std::unique_ptr<pipes::TLS> dtls;
			bool dtls_initialized = false;
	};
}