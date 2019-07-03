#include "pch.h"
#include "Test.h"

using namespace YtCrypto;
using namespace Platform;

namespace YtCrypto
{
	Test::Test(const Platform::Array<uint8, 1u>^ key, const Platform::Array<uint8, 1u>^ iv)
	{
		encctx = (mbedtls_cipher_context_t*)malloc(sizeof(mbedtls_cipher_context_t));
		decctx = (mbedtls_cipher_context_t*)malloc(sizeof(mbedtls_cipher_context_t));
		mbedtls_cipher_init(encctx);
		mbedtls_cipher_init(decctx);
		mbedtls_cipher_setup(encctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CFB128));
		mbedtls_cipher_setup(decctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CFB128));

		mbedtls_cipher_setkey(encctx, key->begin(), 128, MBEDTLS_ENCRYPT);
		mbedtls_cipher_setkey(decctx, key->begin(), 128, MBEDTLS_DECRYPT);
		mbedtls_cipher_set_iv(encctx, iv->begin(), iv->Length);
	}
	unsigned int Test::Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData)
	{
		size_t len;
		mbedtls_cipher_update(encctx, encData->begin(), encData->Length, outData->begin(), &len);
		return len;
	}
	unsigned int Test::Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData)
	{
		auto realDecData = decData->begin();
		auto realLen = decDataLen;
		if (!dec_iv_inited) {
			if (decData->Length < 16) throw ref new InvalidArgumentException("IV not enough");
			mbedtls_cipher_set_iv(decctx, decData->begin(), 16);
			realDecData += 16;
			realLen -= 16;
			dec_iv_inited = true;
		}
		size_t len;
		mbedtls_cipher_update(decctx, realDecData, realLen, outData->begin(), &len);
		return len;
	}
	Test::~Test()
	{
		mbedtls_cipher_free(encctx);
		mbedtls_cipher_free(decctx);
	}
}
