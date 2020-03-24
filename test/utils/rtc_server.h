#pragma once

#include <pipes/ssl.h>
#include <pipes/ws.h>
#include <pipes/rtc/PeerConnection.h>
#include "./socket.h"
#include "../json/json.h"

class rtc_server {
    public:
        struct Client {
            friend class rtc_server;
            public:
                [[nodiscard]] inline rtc::PeerConnection* peer() { return &*this->peer_; }

                void* user_ptr{nullptr};
            private:
                std::weak_ptr<Socket::Client> ws_connection_;

                std::unique_ptr<pipes::SSL> ssl_{nullptr};
                std::unique_ptr<pipes::WebSocket> ws_{nullptr};
                std::unique_ptr<rtc::PeerConnection> peer_{nullptr};

                Json::Reader json_reader_{};
                Json::StreamWriterBuilder json_writer_{};
        };

        typedef std::function<std::shared_ptr<rtc::PeerConnection::Config>(Client*)> callback_peer_connection_config_t;
        typedef std::function<void(const std::shared_ptr<pipes::SSL::Options>& /* options */)> callback_ssl_certificate_initialize_t;

        typedef std::function<void(Client*)> callback_client_connected_t;
        typedef std::function<void(Client*)> callback_client_disconnected_t;

        explicit rtc_server(std::shared_ptr<pipes::Logger> /* logger*/);
        ~rtc_server();

        bool start(std::string& /* error */, int /* port */);
        void stop();

        [[nodiscard]] inline const std::shared_ptr<pipes::Logger>& logger() const { return this->logger_; }

        callback_peer_connection_config_t callback_peer_connection_config;
        callback_ssl_certificate_initialize_t callback_ssl_certificate_initialize;

        callback_client_connected_t callback_client_connected;
        callback_client_disconnected_t callback_client_disconnected;
    private:
        Socket ws_socket_{};
        std::shared_ptr<pipes::Logger> logger_;

        void initialize_client(const std::shared_ptr<Socket::Client>& connection);
        void finalize_client(const std::shared_ptr<Socket::Client>& connection);
};
