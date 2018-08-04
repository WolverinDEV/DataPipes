#pragma once

#include <openssl/evp.h>
#include <include/ssl.h>

namespace pipes {
	class DTLSCertificate {
		public:
			static std::shared_ptr<DTLSCertificate> generate(const std::string& /* name */, int /* days */);
			DTLSCertificate(const std::string& /* certificate pen */, const std::string& /* key pen */);

			X509* getCertificate() const { return this->certificate.get(); }
			EVP_PKEY* getPrivateKey() const { return this->evp_key.get(); }

			std::string getFingerprint() const { return this->fingerprint; }
		private:
			DTLSCertificate(std::shared_ptr<X509> /* certificate */, std::shared_ptr<EVP_PKEY> /* key */);

			std::string fingerprint;
			std::shared_ptr<X509> certificate;
			std::shared_ptr<EVP_PKEY> evp_key;

			void generate_fingerprint();
	};

	class DTLS : public pipes::SSL {
		public:
			bool initialize(std::string& /* error */, const std::shared_ptr<DTLSCertificate>& /* certificate */);

			inline std::shared_ptr<DTLSCertificate> getCertificate() { return this->certificate; }
		private:
			std::shared_ptr<DTLSCertificate> certificate;
	};
}