# - Try to find boringssl include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(BoringSSL)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  BoringSSL_ROOT_DIR          Set this variable to the root installation of
#                            boringssl if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  Crypto_FOUND             System has boringssl, include and library dirs found
#  Crypto_INCLUDE_DIR       The boringssl include directories.
#  Crypto_LIBRARIES         The boringssl libraries.
#  Crypto_CRYPTO_LIBRARY    The boringssl crypto library.
#  Crypto_SSL_LIBRARY       The boringssl ssl library.
#  Crypto_OPENSSL           Set if crypto is openssl
#  Crypto_BORINGSSL         Set if crypto is boringssl

find_path(Crypto_ROOT_DIR
		NAMES INCORPORATING.md include/openssl/ssl.h include/openssl/base.h include/openssl/opensslv.h
		HINTS ${BoringSSL_ROOT_DIR}
)

find_path(Crypto_INCLUDE_DIR
		NAMES openssl/ssl.h openssl/base.h openssl/hkdf.h include/openssl/opensslv.h
		HINTS ${BoringSSL_ROOT_DIR}/include
)

#detect if its boringssl or openssl
file(READ "${Crypto_INCLUDE_DIR}/openssl/crypto.h" BoringSSL_CRYPTO_H)
if(Crypto_CRYPTO_H MATCHES ".*Google Inc.*" OR BoringSSL_CRYPTO_H MATCHES ".*BoringSSL.*")
	set(Crypto_BORINGSSL 1)
elseif(Crypto_CRYPTO_H MATCHES ".*to the OpenSSL project.*" OR BoringSSL_CRYPTO_H MATCHES ".*OpenSSL Project Authors.*")
	set(Crypto_OPENSSL 1)
endif()

find_library(Crypto_SSL_LIBRARY
		NAMES libssl.a
		HINTS ${BoringSSL_ROOT_DIR}/build/ssl
)

find_library(Crypto_CRYPTO_LIBRARY
		NAMES libcrypto.a
		HINTS "${BoringSSL_ROOT_DIR}/build/crypto/"
)

set(Crypto_LIBRARIES ${Crypto_SSL_LIBRARY} ${Crypto_CRYPTO_LIBRARY} CACHE STRING "BoringSSL/OpenSSL SSL and crypto libraries" FORCE)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BoringSSL DEFAULT_MSG
		BoringSSL_LIBRARIES
		BoringSSL_INCLUDE_DIR
)

mark_as_advanced(
		Crypto_ROOT_DIR
		Crypto_INCLUDE_DIR
		Crypto_LIBRARIES
		Crypto_SSL_LIBRARY
		Crypto_CRYPTO_LIBRARY
		Crypto_OPENSSL
		Crypto_BORINGSSL
)