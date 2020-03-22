#pragma once
#include "pch.h"
#include "mbedtls\md5.h"
#include "mbedtls\hkdf.h"
#include "mbedtls\md.h"
#include "utils.h"

namespace winrt::YtCrypto {
	const char SS_AEAD_INFO[10] = "ss-subkey";
	const size_t SS_AEAD_INFO_LEN = strlen(SS_AEAD_INFO);
	const size_t MD5_LEN = 16;
	const size_t SHA224_LEN = 32;
	struct Common
	{
		Common() = delete;
		static uint8_t* LegacyDeriveKey(const uint8_t* password, size_t passwordLen, size_t keyLen) noexcept;
		static bool GenerateIv(uint8_t data[], size_t len) noexcept;
		static bool GenerateKeyMd5(const uint8_t* key, size_t keyLen, const uint8_t* iv, size_t ivLen, uint8_t outBuf[MD5_LEN]) noexcept;
		static int DeriveAuthSessionKeySha1(const uint8_t* salt, size_t saltLen, const uint8_t* masterKey, size_t masterKeyLen, uint8_t* sessionKey, size_t sessionKeyLen) noexcept;
	};
}

