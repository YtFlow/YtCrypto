#pragma once
#include <string>
#include <unordered_map>
#include "CryptorProvider.h"
#include "mbedtls\cipher.h"

namespace YtCrypto {
	class CipherInfo
	{
	public:
		static std::unordered_map<std::wstring, CipherInfo> Ciphers;
		CipherInfo(CryptorProvider provider, mbedtls_cipher_type_t cipherType, size_t keyLen, size_t ivLen)
			: Provider(provider), CipherType(cipherType), KeyLen(keyLen), IvLen(ivLen) {}
		CipherInfo(CryptorProvider provider, mbedtls_cipher_type_t cipherType, size_t keyLen, size_t saltLen, size_t nonceLen, size_t tagLen)
			: Provider(provider), CipherType(cipherType), KeyLen(keyLen), SaltLen(saltLen), NonceLen(nonceLen), TagLen(tagLen) {}

		/* Common fields */
		CryptorProvider Provider;
		mbedtls_cipher_type_t CipherType;
		size_t KeyLen;

		/* Defined for stream ciphers */
		size_t IvLen;

		/* Defined for AEAD ciphers */
		size_t SaltLen;
		size_t NonceLen;
		size_t TagLen;
	};
}

