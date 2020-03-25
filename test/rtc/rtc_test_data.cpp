#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <thread>
#include <cstring>
#include <event2/thread.h>

#include <pipes/ssl.h>
#include <pipes/ws.h>
#include <pipes/rtc/PeerConnection.h>
#include <pipes/rtc/channels/ApplicationChannel.h>

#include "../utils/rtc_server.h"

#include <glib.h>

using namespace std;

void log(void* ptr, pipes::Logger::LogLevel level, const std::string& name, const std::string& msg, ...) {
	auto max_length = 1024 * 2;
	char buffer[max_length];

	va_list args;
	va_start(args, msg);
	max_length = vsnprintf(buffer, max_length, msg.c_str(), args);
	va_end(args);

	printf("[%p][%i][%s] %s\n", ptr, level, name.c_str(), buffer);
}

auto initialize_default_logger() noexcept {
    auto logger = make_shared<pipes::Logger>();
    logger->callback_log = log;
    return logger;
}

auto default_logger = initialize_default_logger();

SSL_CTX* create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

std::string random_string( size_t length )
{
	auto randchar = []() -> char
	{
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};
	std::string str(length,0);
	std::generate_n( str.begin(), length, randchar );
	return str;
}

#define TEST_CERTIFICATE_PATH "test_certificate.pem"
#define TEST_PRIVATE_KEY_PATH "test_private_key.pem"
std::unique_ptr<pipes::TLSCertificate> certificates;

void initializes_certificates() {
	try {
		certificates = make_unique<pipes::TLSCertificate>(TEST_CERTIFICATE_PATH, TEST_PRIVATE_KEY_PATH, true);
		return;
	} catch(const std::exception& ex) {
		cerr << "Failed to load certificates from file: " << ex.what() << endl;
		cerr << "Generating new one" << endl;
	}

	certificates = pipes::TLSCertificate::generate("TeaSpeak-Test", 356);
	assert(certificates);

	certificates->save_file(TEST_CERTIFICATE_PATH, TEST_PRIVATE_KEY_PATH);
}

void initialize_client(rtc_server::Client* client) {
    auto peer = client->peer();

    peer->callback_new_stream = [peer](const std::shared_ptr<rtc::Channel>& stream) {
        cout << "[Stream] Got new stream of type " << stream->type() << " | " << stream->nice_stream_id() << endl;
        if(stream->type() == rtc::CHANTYPE_APPLICATION) {
            auto data_channel = dynamic_pointer_cast<rtc::ApplicationChannel>(stream);
            data_channel->callback_datachannel_new = [peer](const std::shared_ptr<rtc::DataChannel>& channel) {
                weak_ptr<rtc::DataChannel> weak = channel;
                channel->callback_binary = [weak](const pipes::buffer_view& message) {
                    auto chan = weak.lock();
                    cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] Got binary message " << message.length() << endl;

                    pipes::buffer buf;
                    buf += "Echo (BIN): ";
                    buf += message;
                    chan->send(buf, rtc::DataChannel::BINARY);
                };

                channel->callback_text = [weak, peer](const pipes::buffer_view& message) {
                    auto chan = weak.lock();
                    if(message.string() == "close") {
                        cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] closing channel" << endl;
                        chan->close();
                    } else {
                        cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] Got text message " << message.length() << endl;
                        pipes::buffer buf;
                        buf += "Echo (TEXT): ";
                        buf += message;
                        chan->send(buf, rtc::DataChannel::TEXT);
                    }
                };

                channel->callback_close = [weak]() {
                    auto chan = weak.lock();
                    cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] got closed" << endl;
                };
            };
        }
    };
}

void cleanup_client(rtc_server::Client* client) {}

int main() {
	srand(std::chrono::system_clock::now().time_since_epoch().count());
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	evthread_use_pthreads();
	initializes_certificates();

    auto main_loop = std::shared_ptr<GMainLoop>(g_main_loop_new(nullptr, false), g_main_loop_unref);
    std::thread([main_loop]{
        g_main_loop_run(&*main_loop);
    }).detach();

	rtc_server server{default_logger};

    server.callback_peer_connection_config = [main_loop](rtc_server::Client* client){
        auto config = make_shared<rtc::PeerConnection::Config>();
        config->nice_config = make_shared<rtc::NiceWrapper::Config>();

        config->nice_config->main_loop = main_loop;
        config->nice_config->ice_servers.push_back({"stun.l.google.com", 19302});

        config->logger = make_shared<pipes::Logger>();
        config->logger->callback_log = log;
        config->logger->callback_argument = client;
        return config;
    };
    server.callback_ssl_certificate_initialize = [](const std::shared_ptr<pipes::SSL::Options>& options) {
        options->enforce_sni = false;
        options->default_keypair(pipes::SSL::Options::KeyPair{certificates->ref_private_key(), certificates->ref_certificate()});
    };

    server.callback_client_disconnected = cleanup_client;
    server.callback_client_connected = initialize_client;

    std::string error{};
    if(!server.start(error, 1111)) {
        std::cerr << "Failed to start web socket server" << std::endl;;
        return 1;
    }
	std::cout << "Server started on port 1111" << std::endl;


	while(true) this_thread::sleep_for(chrono::seconds(100));
	return 0;
}