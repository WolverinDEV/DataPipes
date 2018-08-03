#include "include/ssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <test/utils/socket.h>
#include <thread>
#include <cstring>
#include <include/ws.h>
#include <include/rtc/PeerConnection.h>
#include "test/json/json.h"

using namespace std;

struct Client {
	std::weak_ptr<Socket::Client> connection;
	unique_ptr<pipes::WebSocket> websocket;
	unique_ptr<rtc::PeerConnection> peer;

	Json::Reader reader;
	Json::StreamWriterBuilder json_writer;
};

auto config = []{
	auto config = make_shared<rtc::PeerConnection::Config>();
	config->nice_config = make_shared<rtc::NiceWrapper::Config>();

	config->nice_config->ice_servers.push_back({"stun.l.google.com", 19302});

	config->nice_config->main_loop = std::shared_ptr<GMainLoop>(g_main_loop_new(nullptr, false), g_main_loop_unref);
	std::thread(g_main_loop_run, config->nice_config->main_loop.get()).detach(); //FIXME

	return config;
}();

void initialize_client(const std::shared_ptr<Socket::Client>& connection) {
	cout << "Got new client" << endl;

	auto client = new Client{};
	client->connection = connection;
	client->websocket = make_unique<pipes::WebSocket>();
	client->peer = make_unique<rtc::PeerConnection>(config);

	{
		client->websocket->initialize();
		client->websocket->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
		client->websocket->direct_process(pipes::PROCESS_DIRECTION_IN, true);


		client->websocket->callback_error([client](int code, const std::string& reason) {
			//if(cl) cl->disconnect(false);
			cout << "Got error: " << code << " => " << reason << endl;

		});
		client->websocket->callback_write([client](const std::string& data) -> void {
			auto cl = client->connection.lock();
			if(cl) cl->send(data);
		});
	}

	{
		string error;
		if(!client->peer->initialize(error)) {
			cerr << "Failed to initialize client! (" << error << ")" << endl; //TODO error handling?
			return;
		}

		client->websocket->callback_data([client](const pipes::WSMessage& message) {
			string error;
			Json::Value root;

			cout << "Got message " << message.data << endl;
			if(client->reader.parse(message.data, root)) {
				std::cout << "Got msg of type: " << root["type"] << "\n";
				if (root["type"] == "offer") {
					std::cout << "Time to get the rtc party started\n";

					client->peer->apply_offer(error, root["msg"]["sdp"].asString());
					Json::Value answer;
					answer["type"] = "answer";
					answer["msg"]["sdp"] = client->peer->generate_answer(true);
					answer["msg"]["type"] = "answer";

					std::cout << "Sending Answer: " << answer << "\n";

					client->websocket->send({pipes::OpCode::TEXT, Json::writeString(client->json_writer, answer)});
				} else if (root["type"] == "candidate") {
					cout << "Apply candidates: " << client->peer->apply_ice_candidates({"a=" + root["msg"]["candidate"].asString()}) << endl;
				}
			} else {
				cerr << "Failed to parse json" << endl;
			}
		});
	}

	{
		client->peer->callback_datachannel_new = [](const std::shared_ptr<rtc::DataChannel>& channel) {
			weak_ptr<rtc::DataChannel> weak = channel;
			channel->callback_binary = [weak](const std::string& message) {
				auto chan = weak.lock();
				cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] Got binary message " << message.length() << endl;
				chan->send("Echo: " + message, rtc::DataChannel::BINARY);
			};
			channel->callback_text = [weak](const std::string& message) {
				auto chan = weak.lock();
				cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] Got text message " << message.length() << endl;
				chan->send("Echo: " + message, rtc::DataChannel::TEXT);
			};
		};
	}

	connection->data = client;
}

int main() {
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	Socket socket{};
	socket.callback_accept = initialize_client;
	socket.callback_read = [](const std::shared_ptr<Socket::Client>& client, const std::string& data) {
		if(client->data)
			((Client*) client->data)->websocket->process_incoming_data(data);
	};
	socket.callback_disconnect = [](const std::shared_ptr<Socket::Client>& client) {
		cout << "Client disconnected" << endl;
	};
	socket.start(1111);


	while(true) this_thread::sleep_for(chrono::seconds(100));
	return 0;
}