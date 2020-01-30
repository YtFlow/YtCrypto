#pragma once
#include "pch.h"
#include "mbedtls\md5.h"
#include "mbedtls\hkdf.h"
#include "mbedtls\md.h"

const size_t MD5_LEN = 16;
namespace YtCrypto {
	const char SS_AEAD_INFO[10] = "ss-subkey";
	const size_t SS_AEAD_INFO_LEN = sizeof(SS_AEAD_INFO);
	class Common
	{
	public:
		static uint8* LegacyDeriveKey(uint8* password, size_t passwordLen, size_t keyLen);
		static uint8* GenerateIv(size_t ivLen);
		static uint8* GenerateKeyMd5(uint8* key, size_t keyLen, uint8* iv, size_t ivLen);
		static int DeriveAuthSessionKeySha1(uint8* salt, size_t saltLen, uint8* masterKey, size_t masterKeyLen, uint8* sessionKey, size_t sessionKeyLen);
	};
}

