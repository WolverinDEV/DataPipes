//
// Created by WolverinDEV on 24/03/2020.
//

#include <iostream>
#include "rtc_server.h"

rtc_server::rtc_server(std::shared_ptr<pipes::Logger> logger) : logger_{std::move(logger)} {
    this->ws_socket_.callback_accept = [&](const auto& client){ this->initialize_client(client); };
    this->ws_socket_.callback_disconnect = [&](const auto& client){ this->finalize_client(client); };

    this->ws_socket_.callback_read = [](const std::shared_ptr<Socket::Client>& client, const pipes::buffer_view& data) {
        if(client->data) {
            auto ptr_client = (Client*) client->data;
            ptr_client->ssl_->process_incoming_data(data);
        }
    };
}

rtc_server::~rtc_server() {
    this->stop();
}

bool rtc_server::start(std::string& error, int port) {
    return this->ws_socket_.start(error, port);
}

void rtc_server::stop() {
    this->ws_socket_.stop();
}

void rtc_server::initialize_client(const std::shared_ptr<Socket::Client> &connection) {
    assert(this->callback_peer_connection_config);
    assert(this->callback_ssl_certificate_initialize);

    auto client = new Client{};
    client->ws_connection_ = connection;
    client->ws_ = std::make_unique<pipes::WebSocket>();
    client->ssl_ = std::make_unique<pipes::SSL>();
    client->peer_ = std::make_unique<rtc::PeerConnection>(this->callback_peer_connection_config(client));

    {
        auto& ssl = *client->ssl_;

        ssl.logger(this->logger_);
        ssl.direct_process(pipes::PROCESS_DIRECTION_OUT, true);
        ssl.direct_process(pipes::PROCESS_DIRECTION_IN, true);

        {

            auto options = std::make_shared<pipes::SSL::Options>();
            options->context_method = SSLv23_method();
            options->type = pipes::SSL::SERVER;
            options->free_unused_keypairs = true;
            options->enforce_sni = true;

            this->callback_ssl_certificate_initialize(options);
            if(!client->ssl_->initialize(options)) {
                std::cerr << "Failed to initialize clients ssl." << std::endl;;
                //TODO: Cleanup client
                return;
            }
        }

        client->ssl_->callback_data([client](const pipes::buffer_view& data) {
            client->ws_->process_incoming_data(data);
        });

        client->ssl_->callback_write([client](const pipes::buffer_view& data) {
            if(auto connection{client->ws_connection_.lock()}; connection)
                connection->send(data);
        });

        client->ssl_->callback_error([client](int code, const std::string& message) {
            std::cerr << "[" << (void*) client << "] Received ssl error (" << code << "/" << message << ")" << std::endl;;
            //TODO: Disconnect client & cleanup
        });
    }

    {
        client->ws_->initialize();
        client->ws_->logger(this->logger_);
        client->ws_->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
        client->ws_->direct_process(pipes::PROCESS_DIRECTION_IN, true);


        client->ws_->callback_error([client](int code, const std::string& message) {
            std::cerr << "[" << (void*) client << "] Received web socket error (" << code << "/" << message << ")" << std::endl;;
            //TODO: Disconnect client & cleanup
        });

        client->ws_->callback_write([client](const pipes::buffer_view& data) {
            client->ssl_->send(data);
        });
    }

    {
        std::string error;
        if(!client->peer_->initialize(error)) {
            std::cerr << "Failed to initialize peer for client: " << error << "" << std::endl;;
            //TODO: Disconnect client & cleanup
            return;
        }

        client->peer_->callback_ice_candidate = [client](const rtc::IceCandidate& ice) {
            Json::Value notify{};
            if(ice.is_finished_candidate()) {
                notify["type"] = "candidate_finish";
                notify["msg"]["candidate"] = "";
                notify["msg"]["sdpMid"] = ice.sdpMid;
                notify["msg"]["sdpMLineIndex"] = ice.sdpMLineIndex;

                std::cout << "[" << (void*) client << "] Sending ice candidate gathering finished notification." << std::endl;;
            } else {
                notify["type"] = "candidate";
                notify["msg"]["candidate"] = ice.candidate;
                notify["msg"]["sdpMid"] = ice.sdpMid;
                notify["msg"]["sdpMLineIndex"] = ice.sdpMLineIndex;

                std::cout << "[" << (void*) client << "] Sending ice candidate for line " << ice.sdpMLineIndex << " (" << ice.sdpMid << "): " << ice.candidate << "" << std::endl;;
            }

            auto raw_data = Json::writeString(client->json_writer_, notify);
            client->ws_->send({pipes::OpCode::TEXT, pipes::buffer_view{raw_data.data(), raw_data.length()}.own_buffer()});
        };

        client->ws_->callback_data([client](const pipes::WSMessage& message) {
            std::string error{};
            Json::Value root{};

            if(client->json_reader_.parse(message.data.string(), root)) {
                if (root["type"] == "offer") {
                    std::cout << "[" << (void*) client << "] Remote side send sdp offer. Applying offer and sending answer" << std::endl;;

                    if(!client->peer_->apply_offer(error, root["msg"]["sdp"].asString())) {
                        std::cerr << "[" << (void*) client << "] Failed to apply remote offer: " << error << std::endl;;
                        //TODO: Disconnect client & cleanup
                        return;
                    }

                    Json::Value answer{};
                    answer["type"] = "answer";
                    answer["msg"]["sdp"] = client->peer_->generate_answer(false);
                    answer["msg"]["type"] = "answer";

                    pipes::buffer buf;
                    buf += Json::writeString(client->json_writer_, answer);
                    client->ws_->send({pipes::OpCode::TEXT, buf});
                } else if (root["type"] == "candidate") {
                    auto candidate = std::make_shared<rtc::IceCandidate>(root["msg"]["candidate"].asString(), root["msg"]["sdpMid"].asString(), root["msg"]["sdpMLineIndex"].asInt());
                    auto result = client->peer_->apply_ice_candidates({candidate});
                    std::cout << "[" << (void*) client << "] Remote side proposed a new candidate. Add result: " << result << "" << std::endl;;
                } else if(root["type"] == "candidate_finish") {
                    std::cout << "[" << (void*) client << "] Remote side finished candidate gathering" << std::endl;;
                    client->peer_->remote_candidates_finished();
                } else {
                    std::cerr << "[" << (void*) client << "] Received a message of an unknown type: " << message.data.string() << "" << std::endl;;
                }
            } else {
                std::cerr << "[" << (void*) client << "] Failed to parse web socket message: " << message.data.string() << "" << std::endl;;
            }
        });
    }

    connection->data = client;
    this->callback_client_connected(client);
}

void rtc_server::finalize_client(const std::shared_ptr<Socket::Client> &connection) {
    if(!connection->data) return;

    auto client = (Client*) connection->data;
    this->callback_client_disconnected(client);

    client->peer_->reset();
    client->peer_ = nullptr;

    client->ws_ = nullptr;
    client->ssl_ = nullptr;
    delete client;
}