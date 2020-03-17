#include "CipherInfo.h"

namespace YtCrypto {
	std::unordered_map<std::wstring, CipherInfo> CipherInfo::Ciphers = {
		/* Stream ciphers */
		{L"rc4-md5", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_ARC4_128, 16, 16}},
		{L"aes-128-cfb", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_128_CFB128, 16, 16}},
		{L"aes-192-cfb", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_192_CFB128, 24, 16}},
		{L"aes-256-cfb", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_256_CFB128, 32, 16}},
		{L"aes-128-ctr", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_128_CTR, 16, 16}},
		{L"aes-192-ctr", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_192_CTR, 24, 16}},
		{L"aes-256-ctr", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_256_CTR, 32, 16}},
		{L"camellia-128-cfb", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_CAMELLIA_128_CFB128, 16, 16}},
		{L"camellia-192-cfb", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_CAMELLIA_192_CFB128, 24, 16}},
		{L"camellia-256-cfb", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_CAMELLIA_256_CFB128, 32, 16}},
		{L"chacha20", {CryptorProvider::SodiumStream, (mbedtls_cipher_type_t)Algorithm::Chacha20, crypto_stream_chacha20_KEYBYTES, crypto_stream_chacha20_NONCEBYTES}},
		{L"chacha20-ietf", {CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_CHACHA20, 32, 12}},

		/* AEAD ciphers */
		{L"aes-128-gcm", {CryptorProvider::MbedtlsAuth, MBEDTLS_CIPHER_AES_128_GCM, 16, 16, 12, 16}},
		{L"aes-192-gcm", {CryptorProvider::MbedtlsAuth, MBEDTLS_CIPHER_AES_192_GCM, 24, 24, 12, 16}},
		{L"aes-256-gcm", {CryptorProvider::MbedtlsAuth, MBEDTLS_CIPHER_AES_256_GCM, 32, 32, 12, 16}},
		{L"chacha20-ietf-poly1305", {CryptorProvider::MbedtlsAuth, MBEDTLS_CIPHER_CHACHA20_POLY1305, 32, 32, 12, 16}},
	};
}
