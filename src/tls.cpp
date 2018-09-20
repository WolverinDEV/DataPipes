//
// Created by wolverindev on 03.08.18.
//

#include <cstring>
#include <utility>
#include "include/tls.h"

using namespace std;
using namespace pipes;

#define ERRORQ(message) \
do { \
	error = message; \
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
bool TLS::initialize(std::string& error, const std::shared_ptr<TLSCertificate> &certificate, TLSMode mode, const initialize_function& fn) {
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

	auto ctx = shared_ptr<SSL_CTX>(SSL_CTX_new(method), ::SSL_CTX_free);
	if (!ctx) ERRORQ("Could not create ctx");

	if (SSL_CTX_set_cipher_list(ctx.get(), "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") != 1) ERRORQ("Failed to set cipher list!");

	SSL_CTX_set_read_ahead(ctx.get(), 1);
	SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_peer_certificate);
	SSL_CTX_use_PrivateKey(ctx.get(), certificate->getPrivateKey());
	SSL_CTX_use_certificate(ctx.get(), certificate->getCertificate());
	if (SSL_CTX_check_private_key(ctx.get()) != 1)  ERRORQ("Failed to verify key!");

	if(fn && !fn(ctx.get())) return false;
	if(!SSL::initialize(ctx, SSL::CLIENT)) ERRORQ("SSL initialize failed!");

	std::shared_ptr<EC_KEY> ecdh = std::shared_ptr<EC_KEY>(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
	SSL_set_options(this->sslLayer, SSL_OP_SINGLE_ECDH_USE);
	SSL_set_tmp_ecdh(this->sslLayer, ecdh.get());

	return true;
}

//TODO improve with unique_ptr to return at any error
TLSCertificate::TLSCertificate(const std::string &pem_certificate, const std::string &pem_key) {
	/* x509 */
	BIO *bio = BIO_new(BIO_s_mem());
	BIO_write(bio, pem_certificate.c_str(), (int)pem_certificate.length());

	this->certificate = std::shared_ptr<X509>(PEM_read_bio_X509(bio, nullptr, 0, 0), X509_free);
	BIO_free(bio);
	if (!this->certificate) {
		throw std::invalid_argument("Could not read cert_pem");
	}

	/* evp_pkey */
	bio = BIO_new(BIO_s_mem());
	BIO_write(bio, pem_key.c_str(), (int)pem_key.length());

	this->evp_key = std::shared_ptr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio, nullptr, 0, 0), EVP_PKEY_free);
	BIO_free(bio);

	if (!this->evp_key) {
		throw std::invalid_argument("Could not read pkey_pem");
	}

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

std::shared_ptr<TLSCertificate> TLSCertificate::generate(const std::string &common_name, int days) {
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
	return shared_ptr<TLSCertificate>(new TLSCertificate(cert, pkey));
}