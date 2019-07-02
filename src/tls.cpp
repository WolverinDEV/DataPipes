//
// Created by wolverindev on 03.08.18.
//

#include <cstring>
#include <utility>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "include/tls.h"

using namespace std;
using namespace pipes;

#define ERRORQ(message) \
do { \
	error = message; \
	return false; \
} while(0)

#define ERRORQ_I(message) \
do { \
	return false; \
} while(0)

static int verify_peer_certificate(int ok, X509_STORE_CTX *ctx) {
	// XXX: This function should ask the user if they trust the cert
	return 1;
}

/*
	EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if(ecdh == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]   Error creating ECDH group! (%s)\n",
			handle->handle_id, ERR_reason_error_string(ERR_get_error()));
		janus_refcount_decrease(&dtls->ref);
		return NULL;
	}
	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_ECDH_USE;
	SSL_set_options(dtls->ssl, flags);
	SSL_set_tmp_ecdh(dtls->ssl, ecdh);
	EC_KEY_free(ecdh);
 */
bool TLS::initialize(std::string& error, const std::shared_ptr<TLSCertificate> &certificate, TLSMode mode, Type handshake_mode, const initialize_function& fn) {
	this->certificate = certificate;

	const SSL_METHOD* method = nullptr;
	switch(mode) {
		case TLSMode::TLS_X:
			method = TLS_method();
			break;
		case TLSMode::TLS_v1:
			method = TLSv1_method();
			break;
		case TLSMode::TLS_v1_1:
			method = TLSv1_1_method();
			break;
		case TLSMode::TLS_v1_2:
			method = TLSv1_2_method();
			break;

		case DTLS_X:
			method = DTLS_method();
			break;
		case DTLS_v1:
			method = DTLSv1_method();
			break;
		case DTLS_v1_2:
			method = DTLSv1_2_method();
			break;

		default:
			error = "Invalid mode";
			return false;
	}

	auto options = make_shared<SSL::Options>();
	options->type = handshake_mode;
	options->context_method = method;
	options->free_unused_keypairs = true;
	options->context_initializer = [&, fn](SSL_CTX* context) {
		if (SSL_CTX_set_cipher_list(context, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") != 1)
			ERRORQ_I("Failed to set cipher list!");

		SSL_CTX_set_read_ahead(context, 1);
		SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_peer_certificate);
		SSL_CTX_use_PrivateKey(context, certificate->getPrivateKey());
		SSL_CTX_use_certificate(context, certificate->getCertificate());

		if (SSL_CTX_check_private_key(context) != 1)
			ERRORQ_I("Failed to verify key!");

		if(fn && !fn(context))
			return false;
		return true;
	};
	options->ssl_initializer = [&](::SSL* ssl) {
		std::shared_ptr<EC_KEY> ecdh = std::shared_ptr<EC_KEY>(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
		SSL_set_options(this->sslLayer, SSL_OP_SINGLE_ECDH_USE);
		SSL_set_tmp_ecdh(this->sslLayer, ecdh.get());
		return true;
	};

	if(!SSL::initialize(options)) ERRORQ("SSL initialize failed!");
	return true;
}

#define HAVE_STD_EXPERIMENTAL_FS
#if defined(HAVE_STD_FS) || defined(HAVE_STD_EXPERIMENTAL_FS)
	#ifdef HAVE_STD_FS
		#include <filesystem>
		namespace fs = std::filesystem;
	#else
		#include <experimental/filesystem>
		namespace fs = std::experimental::filesystem;
	#endif
#endif


std::string ssl_err_as_string () {
	std::unique_ptr<BIO, decltype(BIO_free)*> bio(BIO_new(BIO_s_mem()), BIO_free);
	ERR_print_errors(bio.get());

	char* buf = nullptr;
	long len = BIO_get_mem_data(bio.get(), &buf);
	return string(buf, len);
}

TLSCertificate::TLSCertificate(const std::string &pem_certificate, const std::string &pem_key, bool files) {
	std::unique_ptr<BIO, decltype(BIO_free)*> bio_certificate(nullptr, BIO_free);
	std::unique_ptr<BIO, decltype(BIO_free)*> bio_key(nullptr, BIO_free);

	if(files) {
		#if defined(HAVE_STD_FS) || defined(HAVE_STD_EXPERIMENTAL_FS)
			auto path_key = fs::path(pem_key);
			auto path_certificate = fs::path(pem_certificate);

			if(!fs::exists(path_key)) throw std::invalid_argument("Missing key file!");
			if(!fs::exists(path_certificate)) throw std::invalid_argument("Missing certificate file!");

			bio_key.reset(BIO_new_file(pem_key.c_str(), "r"));
			bio_certificate.reset(BIO_new_file(pem_certificate.c_str(), "r"));
		#else
			throw std::runtime_error("file system isn't implemented!");
		#endif
	} else {
		bio_key.reset(BIO_new(BIO_s_mem()));
		BIO_write(bio_key.get(), pem_key.c_str(), (int)pem_key.length());

		bio_certificate.reset(BIO_new(BIO_s_mem()));
		BIO_write(bio_certificate.get(), pem_certificate.c_str(), (int)pem_certificate.length());
	}

	/* x509 */
	this->certificate = std::shared_ptr<X509>(PEM_read_bio_X509(bio_certificate.get(), nullptr, nullptr, nullptr), X509_free);
	if (!this->certificate)
		throw std::invalid_argument("Could not read cert_pem (" + ssl_err_as_string() + ")");

	/* evp_pkey */
	this->evp_key = std::shared_ptr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio_key.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (!this->evp_key)
		throw std::invalid_argument("Could not read pkey_pem (" + ssl_err_as_string() + ")");

	this->generate_fingerprint();
}

TLSCertificate::TLSCertificate(std::shared_ptr<X509> certificate, std::shared_ptr<EVP_PKEY> key) : certificate(std::move(certificate)), evp_key(std::move(key)) {
	this->generate_fingerprint();
}

#define SHA256_FINGERPRINT_SIZE (95 + 1)
void TLSCertificate::generate_fingerprint() {
	unsigned int len;
	unsigned char buf[4096] = {0};
	if (!X509_digest(this->certificate.get(), EVP_sha256(), buf, &len)) {
		throw std::runtime_error("GenerateFingerprint(): X509_digest error");
	}

	if (len > SHA256_FINGERPRINT_SIZE) {
		throw std::runtime_error("GenerateFingerprint(): fingerprint size too large for buffer!");
	}

	int offset = 0;
	char fp[SHA256_FINGERPRINT_SIZE];
	memset(fp, 0, SHA256_FINGERPRINT_SIZE);
	for (unsigned int i = 0; i < len; ++i) {
		snprintf(fp + offset, 4, "%02X:", buf[i]);
		offset += 3;
	}
	fp[offset - 1] = '\0';
	this->fingerprint = string(fp);
}


static std::shared_ptr<X509> GenerateX509(std::shared_ptr<EVP_PKEY> evp_pkey, const std::string &common_name, int days) {
	std::shared_ptr<X509> null_result;

	std::shared_ptr<X509> x509(X509_new(), X509_free);
	std::shared_ptr<BIGNUM> serial_number(BN_new(), BN_free);
	std::shared_ptr<X509_NAME> name(X509_NAME_new(), X509_NAME_free);

	if (!x509 || !serial_number || !name) {
		return null_result;
	}

	if (!X509_set_pubkey(x509.get(), evp_pkey.get())) {
		return null_result;
	}

	if (!BN_pseudo_rand(serial_number.get(), 64, 0, 0)) {
		return null_result;
	}

	ASN1_INTEGER *asn1_serial_number = X509_get_serialNumber(x509.get());
	if (!asn1_serial_number) {
		return null_result;
	}

	if (!BN_to_ASN1_INTEGER(serial_number.get(), asn1_serial_number)) {
		return null_result;
	}

	if (!X509_set_version(x509.get(), 0L)) {
		return null_result;
	}

	if (!X509_NAME_add_entry_by_NID(name.get(), NID_commonName, MBSTRING_UTF8, (unsigned char *)common_name.c_str(), -1, -1, 0)) {
		return null_result;
	}

	if (!X509_set_subject_name(x509.get(), name.get()) || !X509_set_issuer_name(x509.get(), name.get())) {
		return null_result;
	}

	if (!X509_gmtime_adj(X509_get_notBefore(x509.get()), 0) || !X509_gmtime_adj(X509_get_notAfter(x509.get()), days * 24 * 3600)) {
		return null_result;
	}

	if (!X509_sign(x509.get(), evp_pkey.get(), EVP_sha1())) {
		return null_result;
	}

	return x509;
}

std::unique_ptr<TLSCertificate> TLSCertificate::generate(const std::string &common_name, int days) {
	std::shared_ptr<EVP_PKEY> pkey(EVP_PKEY_new(), EVP_PKEY_free);
	RSA *rsa = RSA_new();

	std::shared_ptr<BIGNUM> exponent(BN_new(), BN_free);

	if (!pkey || !rsa || !exponent) {
		throw std::runtime_error("GenerateCertificate: !pkey || !rsa || !exponent");
	}

	if (!BN_set_word(exponent.get(), 0x10001) || !RSA_generate_key_ex(rsa, 1024, exponent.get(), NULL) || !EVP_PKEY_assign_RSA(pkey.get(), rsa)) {
		throw std::runtime_error("GenerateCertificate: Error generating key");
	}
	auto cert = GenerateX509(pkey, common_name, days);

	if (!cert) {
		throw std::runtime_error("GenerateCertificate: Error in GenerateX509");
	}

	return unique_ptr<TLSCertificate>(new TLSCertificate(cert, pkey));
}

bool TLSCertificate::save(std::string &certificate, std::string &key, bool files) {
	if(files) return this->save_file(certificate, key);

	assert(false); //FIXME: Implement me
	return false;
}

bool TLSCertificate::save_file(const std::string &certificate_path, const std::string &key_path) {
	std::unique_ptr<BIO, decltype(BIO_free)*> bio(nullptr, BIO_free);

	bio.reset(BIO_new_file(key_path.c_str(), "w"));
	if(PEM_write_bio_PrivateKey(bio.get(), this->evp_key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) return false;

	bio.reset(BIO_new_file(certificate_path.c_str(), "w"));
	if(PEM_write_bio_X509(bio.get(), this->certificate.get()) != 1) return false;

	return true;
}

std::shared_ptr<X509> TLSCertificate::ref_certificate() {
	return this->certificate;
}

std::shared_ptr<EVP_PKEY> TLSCertificate::ref_private_key() {
	return this->evp_key;
}