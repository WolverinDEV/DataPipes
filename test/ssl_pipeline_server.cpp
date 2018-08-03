#include "include/ssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <test/utils/socket.h>
#include <thread>
#include <assert.h>
#include <cstring>

using namespace std;

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

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


#define CERTIFICATE_FILE "/home/wolverindev/TeamSpeak/server/environment/default_certificate.pem"
#define KEY_FILE "/home/wolverindev/TeamSpeak/server/environment/default_privatekey.pem"

std::pair<EVP_PKEY*, X509*> createCerts(pem_password_cb* password) {
/*
	auto bio = BIO_new_file("cert.pem", "r");
	if(!bio) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	auto cert = PEM_read_bio_X509(bio, nullptr, password, nullptr);
	if(!cert) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	BIO_free(bio);


	bio = BIO_new_file("key.pem", "r");
	if(!bio) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	auto key = PEM_read_bio_PrivateKey(bio, nullptr, password, nullptr);

	if(!key) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	BIO_free(bio);
*/

    auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(EVP_PKEY_new(), ::EVP_PKEY_free);

    auto rsa = RSA_new();
    auto e = std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_new(), ::BN_free);
    BN_set_word(e.get(), RSA_F4);
    if(!RSA_generate_key_ex(rsa, 2048, e.get(), nullptr)) return {nullptr, nullptr};
    EVP_PKEY_assign_RSA(key.get(), rsa);

    auto cert = X509_new();
    X509_set_pubkey(cert, key.get());

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 3);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    X509_NAME* name = X509_get_subject_name(cert);

    //This was an example for TeaSpeak
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *) "DE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *) "TeaSpeak", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC, (unsigned char *) "Web Server", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "emailAddress",  MBSTRING_ASC, (unsigned char *)"contact@teaspeak.de", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"web.teaspeak.de", -1, -1, 0);

    X509_set_issuer_name(cert, name);
    X509_set_subject_name(cert, name);

    X509_sign(cert, key.get(), EVP_sha512());

    return {key.release(), cert};
};

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);
    auto certs = createCerts([](char* buffer, int length, int rwflag, void* data) -> int {
        std::string password = "markus";
        memcpy(buffer, password.data(), password.length());
        return password.length();
    });

    PEM_write_X509(stdout, certs.second);

    if (SSL_CTX_use_PrivateKey(ctx, certs.first) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate(ctx, certs.second) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void initialize_client(const std::shared_ptr<Socket::Client>& client) {
    cout << "Got new client" << endl;
    auto ssl_pipeline = new pipes::SSL{};

    {
        auto ctx = create_context();
        configure_context(ctx);
        ssl_pipeline->initialize(shared_ptr<SSL_CTX>(ctx, SSL_CTX_free), pipes::SSL::SERVER);
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

    ssl_pipeline->callback_data([weak](const string& data) {
        cout << "Got data " << data << endl;
    });

    ssl_pipeline->callback_write([weak](const std::string& data) -> void {
        auto cl = weak.lock();
        if(cl) cl->send(data);
    });

    client->data = ssl_pipeline;
}

int main() {
    init_openssl();


    Socket socket{};
    socket.callback_accept = initialize_client;
    socket.callback_read = [](const std::shared_ptr<Socket::Client>& client, const std::string& data) {
        ((pipes::SSL*) client->data)->process_incoming_data(data);
    };
    socket.callback_disconnect = [](const std::shared_ptr<Socket::Client>& client) {
        cout << "Client disconnected" << endl;
    };
    socket.start(1111);


    while(true) this_thread::sleep_for(chrono::seconds(100));
    return 0;
}