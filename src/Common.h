#pragma once
#include "pch.h"
#include "mbedtls\md5.h"

const size_t MD5_LEN = 16;
namespace YtCrypto {
	class Common
	{
	public:
		static uint8* LegacyDeriveKey(uint8* password, size_t passwordLen, size_t keyLen);
		static uint8* GenerateIv(size_t ivLen);
		static uint8* GenerateKeyMd5(uint8* key, size_t keyLen, uint8* iv, size_t ivLen);
	};
}

