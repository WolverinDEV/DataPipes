#include "./utils/socket.h"
#include <pipes/ssl.h>
#include <pipes/tls.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <thread>
#include <cstring>

using namespace std;

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

std::string currentDateTime() {
	time_t     now{time(nullptr)};
	struct tm  tstruct{};
	char       buf[80];
	tstruct = *localtime(&now);
	// Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
	// for more information about date/time format
	strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

	return buf;
}

void log(pipes::Logger::LogLevel level, const std::string& name, const std::string& message, ...) {
	auto max_length = 1024 * 8;
	char buffer[max_length];

	va_list args;
	va_start(args, message);
	max_length = vsnprintf(buffer, max_length, message.c_str(), args);
	va_end(args);

	printf("[%s][%i][%s] %s\n", currentDateTime().c_str(), level, name.c_str(), buffer);
}

auto logger = []{
	auto logger = make_shared<pipes::Logger>();
	logger->callback_log = log;
	return logger;
}();


#define TEST_CERTIFICATE_PATH "test_certificate.pem"
#define TEST_PRIVATE_KEY_PATH "test_private_key.pem"
std::unique_ptr<pipes::TLSCertificate> certificates;
auto certificates2 = pipes::TLSCertificate::generate("DataPipes", 356);

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

void initialize_client(const std::shared_ptr<Socket::Client>& client) {
    cout << "Got new client" << endl;
    auto ssl_pipeline = new pipes::SSL{};

    {

        auto options = make_shared<pipes::SSL::Options>();
	    options->context_method = SSLv23_method();
        options->type = pipes::SSL::SERVER;
        options->free_unused_keypairs = true;
	    options->enforce_sni = true;
        options->default_keypair(pipes::SSL::Options::KeyPair{certificates->ref_private_key(), certificates->ref_certificate()});
	    options->servername_keys["test"] = {certificates2->ref_private_key(), certificates2->ref_certificate()};
        if(!ssl_pipeline->initialize(options)) {
        	cerr << "Failed to initialize client" << endl;
        	delete ssl_pipeline;
        	return;
        }
    }

    ssl_pipeline->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
    ssl_pipeline->direct_process(pipes::PROCESS_DIRECTION_IN, true);

    weak_ptr<Socket::Client> weak = client;
    ssl_pipeline->callback_error([weak](int code, const std::string& reason) {
        auto cl = weak.lock();
        //if(cl) cl->disconnect(false);
        cout << "Got error: " << code << " => " << reason << endl;

    });

    ssl_pipeline->callback_initialized = [](){
        cout << "INIT!" << endl;
    };

    ssl_pipeline->callback_data([weak](const pipes::buffer_view& data) {
        cout << "Got data " << data << endl;
    });

    ssl_pipeline->callback_write([weak](const pipes::buffer_view& data) -> void {
        auto cl = weak.lock();
        if(cl) cl->send(data);
    });

    ssl_pipeline->logger(logger);

    client->data = ssl_pipeline;
}

int main() {
    init_openssl();
    initializes_certificates();

    Socket socket{};
    socket.callback_accept = initialize_client;
    socket.callback_read = [](const std::shared_ptr<Socket::Client>& client, const pipes::buffer_view& data) {
    	cout << "Read " << data.length() << "bytes" << endl;
    	if(client->data)
            ((pipes::SSL*) client->data)->process_incoming_data(data);
    };
    socket.callback_disconnect = [](const std::shared_ptr<Socket::Client>& client) {
        cout << "Client disconnected" << endl;
    };
    socket.start(1111);


    while(true) this_thread::sleep_for(chrono::seconds(100));
    return 0;
}