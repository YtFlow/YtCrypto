#include "Common.h"

namespace winrt::YtCrypto {
	// https://github.com/shadowsocks/shadowsocks-windows/blob/master/shadowsocks-csharp/Encryption/Stream/StreamEncryptor.cs#L71
	uint8_t* Common::LegacyDeriveKey(const uint8_t* password, size_t passwordLen, size_t keyLen) noexcept
	{
		uint8_t* key = (uint8_t*)malloc(keyLen);
		if (key == NULL) {
			return NULL;
		}
		size_t resultLen = passwordLen + MD5_LEN;
		uint8_t* result = (uint8_t*)malloc(resultLen);
		if (result == NULL) {
			free(key);
			return NULL;
		}
		size_t i = 0;
		uint8_t md5sum[MD5_LEN];
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

	bool Common::GenerateIv(uint8_t data[], size_t len) noexcept
	{
		return SUCCEEDED(BCryptGenRandom(nullptr, data, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
	}

	// https://github.com/shadowsocks/shadowsocks-windows/blob/master/shadowsocks-csharp/Encryption/Stream/StreamMbedTLSEncryptor.cs#L61
	bool Common::GenerateKeyMd5(const uint8_t* key, size_t keyLen, const uint8_t* iv, size_t ivLen, uint8_t outBuf[MD5_LEN]) noexcept
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
	int Common::DeriveAuthSessionKeySha1(const uint8_t* salt, size_t saltLen, const uint8_t* masterKey, size_t masterKeyLen, uint8_t* sessionKey, size_t sessionKeyLen) noexcept
	{
		auto md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
		return mbedtls_hkdf(md, salt, saltLen, masterKey, masterKeyLen, (const unsigned char*)SS_AEAD_INFO, SS_AEAD_INFO_LEN, sessionKey, sessionKeyLen);
	}
}

