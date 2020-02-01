#pragma once
#include "pch.h"
#include "mbedtls\md5.h"
#include "mbedtls\hkdf.h"
#include "mbedtls\md.h"

namespace YtCrypto {
	const char SS_AEAD_INFO[10] = "ss-subkey";
	const size_t SS_AEAD_INFO_LEN = sizeof(SS_AEAD_INFO);
	const size_t MD5_LEN = 16;
	class Common
	{
	public:
		static uint8* LegacyDeriveKey(const uint8* password, size_t passwordLen, size_t keyLen);
		static uint8* GenerateIv(size_t ivLen);
		static bool GenerateKeyMd5(const uint8* key, size_t keyLen, const uint8* iv, size_t ivLen, uint8* outBuf);
		static int DeriveAuthSessionKeySha1(const uint8* salt, size_t saltLen, const uint8* masterKey, size_t masterKeyLen, uint8* sessionKey, size_t sessionKeyLen);
	};
}

