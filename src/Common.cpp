#include "Common.h"

namespace YtCrypto {
	// https://github.com/shadowsocks/shadowsocks-windows/blob/master/shadowsocks-csharp/Encryption/Stream/StreamEncryptor.cs#L71
	uint8* Common::LegacyDeriveKey(const uint8* password, size_t passwordLen, size_t keyLen)
	{
		uint8* key = (uint8*)malloc(keyLen);
		size_t resultLen = passwordLen + MD5_LEN;
		uint8* result = (uint8*)malloc(resultLen);
		size_t i = 0;
		uint8 md5sum[MD5_LEN];
		while (i < keyLen) {
			if (i == 0) {
				if (mbedtls_md5_ret(password, passwordLen, md5sum)) goto ERR;
			}
			else {
				// passwordLen + MD5_LEN >= MD5_LEN
				if (memcpy_s(result, resultLen, md5sum, MD5_LEN)) goto ERR;
				// passwordLen == passwordLen
				if (memcpy_s(result + MD5_LEN, passwordLen, password, passwordLen)) goto ERR;
				if (mbedtls_md5_ret(result, resultLen, md5sum)) goto ERR;
			}
			// keyLen - i >= min(MD5_LEN, keyLen - i)
			if (memcpy_s(key + i, keyLen - i, md5sum, min(MD5_LEN, keyLen - i))) goto ERR;
			i += MD5_LEN;
		}
		free(result);
		return key;

	ERR:
		free(result);
		free(key);
		return NULL;
	}

	uint8* Common::GenerateIv(size_t ivLen)
	{
		uint8* ret = (uint8*)malloc(ivLen);
		if (FAILED(BCryptGenRandom(nullptr, ret, (ULONG)ivLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
			free(ret);
			ret = NULL;
		}
		return ret;
	}

	// https://github.com/shadowsocks/shadowsocks-windows/blob/master/shadowsocks-csharp/Encryption/Stream/StreamMbedTLSEncryptor.cs#L61
	bool Common::GenerateKeyMd5(const uint8* key, size_t keyLen, const uint8* iv, size_t ivLen, uint8* outBuf)
	{
		mbedtls_md5_context md5Ctx;
		mbedtls_md5_init(&md5Ctx);
		if (mbedtls_md5_starts_ret(&md5Ctx)) goto ERR;
		if (mbedtls_md5_update_ret(&md5Ctx, key, keyLen)) goto ERR;
		if (mbedtls_md5_update_ret(&md5Ctx, iv, ivLen)) goto ERR;
		if (mbedtls_md5_finish_ret(&md5Ctx, outBuf)) goto ERR;
		mbedtls_md5_free(&md5Ctx);
		return true;

	ERR:
		mbedtls_md5_free(&md5Ctx);
		return false;
	}

	// https://github.com/shadowsocks/libsscrypto/blob/master/libsscrypto/hkdf.c#L87
	int Common::DeriveAuthSessionKeySha1(const uint8* salt, size_t saltLen, const uint8* masterKey, size_t masterKeyLen, uint8* sessionKey, size_t sessionKeyLen)
	{
		auto md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
		return mbedtls_hkdf(md, salt, saltLen, masterKey, masterKeyLen, (const unsigned char *)SS_AEAD_INFO, SS_AEAD_INFO_LEN, sessionKey, sessionKeyLen);
	}
}

