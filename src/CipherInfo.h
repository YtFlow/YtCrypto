#pragma once
#include "pch.h"
#include <unordered_map>
#include "mbedtls\cipher.h"
#include "crypto_stream_chacha20.h"
#include "crypto_stream_salsa20.h"
#include "crypto_aead_chacha20poly1305.h"
#include "crypto_aead_xchacha20poly1305.h"
#include "CryptorProvider.h"
#include "Algorithm.h"

namespace YtCrypto {
	class CipherInfo
	{
	public:
		static std::unordered_map<winrt::hstring, std::shared_ptr<CipherInfo>> Ciphers;
		CipherInfo(CryptorProvider provider, mbedtls_cipher_type_t cipherType, int keyLen, int ivLen)
			: Provider(provider), CipherType(cipherType), KeyLen(keyLen), IvLen(ivLen) {}
		CipherInfo(CryptorProvider provider, mbedtls_cipher_type_t cipherType, int keyLen, int saltLen, int nonceLen, int tagLen)
			: Provider(provider), CipherType(cipherType), KeyLen(keyLen), IvLen(saltLen), NonceLen(nonceLen), TagLen(tagLen) {}

		/* Common fields */
		CryptorProvider Provider;
		mbedtls_cipher_type_t CipherType;
		int KeyLen;
		int IvLen;

		/* Defined for AEAD ciphers */
		// int SaltLen; // Reuse IvLen
		int NonceLen;
		int TagLen;
	};
}

