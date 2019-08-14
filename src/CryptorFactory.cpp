#include "CryptorFactory.h"
#include "mbedtls/md5.h"
#include <cstdlib>
#include <cstring>
#include <Windows.h>
#include <bcrypt.h>

namespace YtCrypto {
	ICryptor ^ CryptorFactory::CreateCryptor() {
		uint8 *iv = GenerateIv(ivLen);
		if (iv == NULL) {
			throw ref new Platform::FailureException(L"Cannot generate IV");
		}
		switch (provider) {
		case CryptorProvider::Mbedtls:
			return ref new MbedStreamCryptor(key, keyLen * 8, iv, ivLen, mbedtls_cipher_type);
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
		else {
			throw ref new Platform::NotImplementedException(L"The given cipher is not supported yet");
		}

		// Derive key
		key = LegacyDeriveKey(password->Data, password->Length, keyLen);
	}

	CryptorFactory::~CryptorFactory()
	{
		// Key data are shared among all cryptor instances
		free(key);
	}

	// https://github.com/shadowsocks/shadowsocks-windows/blob/master/shadowsocks-csharp/Encryption/Stream/StreamEncryptor.cs#L71
	uint8 * CryptorFactory::LegacyDeriveKey(uint8 * password, size_t passwordLen, size_t keyLen)
	{
		uint8 *key = (uint8*)malloc(keyLen);
		size_t resultLen = passwordLen + MD5_LEN;
		uint8 *result = (uint8*)malloc(resultLen);
		size_t i = 0;
		uint8 md5sum[MD5_LEN];
		while (i < keyLen) {
			if (i == 0) {
				mbedtls_md5(password, passwordLen, md5sum);
			}
			else {
				// passwordLen + MD5_LEN >= MD5_LEN
				memcpy_s(result, resultLen, md5sum, MD5_LEN);
				// passwordLen == passwordLen
				memcpy_s(result + MD5_LEN, passwordLen, password, passwordLen);
				mbedtls_md5(result, resultLen, md5sum);
			}
			// keyLen - i >= min(MD5_LEN, keyLen - i)
			memcpy_s(key + i, keyLen - i, md5sum, min(MD5_LEN, keyLen - i));
			i += MD5_LEN;
		}
		free(result);
		return key;
	}
	uint8 * CryptorFactory::GenerateIv(size_t ivLen)
	{
		uint8 *ret = (uint8*)malloc(ivLen);
		if (FAILED(BCryptGenRandom(nullptr, ret, ivLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
			free(ret);
			ret = NULL;
		}
		return ret;
	}

}
