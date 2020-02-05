#pragma once
#include "pch.h"
#include "mbedtls\md5.h"
#include "mbedtls\hkdf.h"
#include "mbedtls\md.h"
#include "mbedtls\sha256.h"

namespace YtCrypto {
	const char SS_AEAD_INFO[10] = "ss-subkey";
	const size_t SS_AEAD_INFO_LEN = strlen(SS_AEAD_INFO);
	const size_t MD5_LEN = 16;
	const size_t SHA224_LEN = 32;
	public ref class Common sealed
	{
	internal:
		static uint8* LegacyDeriveKey(const uint8* password, size_t passwordLen, size_t keyLen);
		static uint8* GenerateIv(size_t ivLen);
		static bool GenerateKeyMd5(const uint8* key, size_t keyLen, const uint8* iv, size_t ivLen, uint8 outBuf[MD5_LEN]);
		static int DeriveAuthSessionKeySha1(const uint8* salt, size_t saltLen, const uint8* masterKey, size_t masterKeyLen, uint8* sessionKey, size_t sessionKeyLen);
		static int Sha224(const uint8* input, size_t size, uint8 outBuf[32]);
		static void SodiumIncrement(unsigned char* n, const size_t nlen);
	public:
		static int Sha224(const Platform::Array<uint8, 1u>^ key, Platform::WriteOnlyArray<uint8, 1u>^ outBuf);
	};
}

