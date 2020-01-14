#include "CryptorFactory.h"
#include "mbedtls/md5.h"
#include <cstdlib>
#include <cstring>
#include <Windows.h>
#include <bcrypt.h>

namespace YtCrypto {
	ICryptor ^ CryptorFactory::CreateCryptor() {
		auto iv = std::unique_ptr<uint8>(Common::GenerateIv(ivLen));
		if (iv == nullptr) {
			throw ref new Platform::FailureException(L"Cannot generate IV");
		}

		switch (provider) {
		case CryptorProvider::Mbedtls:
			return ref new MbedStreamCryptor(key, keyLen, std::move(iv), ivLen, mbedtls_cipher_type);
		default:
			throw ref new Platform::NotImplementedException(L"Cannot create a cryptor with an unknown provider");
		}
	}

	CryptorFactory::CryptorFactory(Platform::String^ method, const Platform::Array<uint8, 1>^ password) {
		provider = CryptorProvider::Mbedtls;
		ivLen = 16;
		keyLen = 16;
		if (method == "aes-128-cfb") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_AES_128_CFB128;
		}
		else if (method == "aes-192-cfb") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_AES_192_CFB128;
			keyLen = 24;
		}
		else if (method == "aes-256-cfb") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_AES_256_CFB128;
			keyLen = 32;
		}
		else if (method == "aes-128-ctr") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_AES_128_CTR;
		}
		else if (method == "aes-192-ctr") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_AES_192_CTR;
			keyLen = 24;
		}
		else if (method == "aes-256-ctr") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_AES_256_CTR;
			keyLen = 32;
		}
		else if (method == "camellia-128-cfb") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_CAMELLIA_128_CFB128;
		}
		else if (method == "camellia-192-cfb") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_CAMELLIA_192_CFB128;
			keyLen = 24;
		}
		else if (method == "camellia-256-cfb") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_CAMELLIA_256_CFB128;
			keyLen = 32;
		}
		else if (method == "chacha20-ietf") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_CHACHA20;
			keyLen = 32;
			ivLen = 12;
		}
		else if (method == "rc4-md5") {
			mbedtls_cipher_type = MBEDTLS_CIPHER_ARC4_128;
		}
		else {
			throw ref new Platform::NotImplementedException(L"The given cipher is not supported yet");
		}

		// Derive key
		key = std::shared_ptr<uint8>(Common::LegacyDeriveKey(password->Data, password->Length, keyLen));
		if (key == nullptr) {
			throw ref new Platform::FailureException(L"Cannot derive key");
		}
	}

	CryptorFactory::~CryptorFactory()
	{
		// Key data are shared among all cryptor instances
		// free(key);
	}
}
