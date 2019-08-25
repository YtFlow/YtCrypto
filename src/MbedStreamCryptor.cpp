#include "pch.h"
#include "MbedStreamCryptor.h"

using namespace YtCrypto;
using namespace Platform;

namespace YtCrypto
{
	MbedStreamCryptor::MbedStreamCryptor(uint8 *key, size_t keyBitLen, uint8 *iv, size_t ivLen, mbedtls_cipher_type_t cipher_type) : key(key), iv(iv), ivLen(ivLen)
	{
		encctx = (mbedtls_cipher_context_t*)malloc(sizeof(mbedtls_cipher_context_t));
		decctx = (mbedtls_cipher_context_t*)malloc(sizeof(mbedtls_cipher_context_t));
		mbedtls_cipher_init(encctx);
		mbedtls_cipher_init(decctx);
		mbedtls_cipher_setup(encctx, mbedtls_cipher_info_from_type(cipher_type));
		mbedtls_cipher_setup(decctx, mbedtls_cipher_info_from_type(cipher_type));

		mbedtls_cipher_setkey(encctx, key, keyBitLen, MBEDTLS_ENCRYPT);
		mbedtls_cipher_setkey(decctx, key, keyBitLen, MBEDTLS_DECRYPT);
		mbedtls_cipher_set_iv(encctx, iv, ivLen);
	}
	size_t MbedStreamCryptor::Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData)
	{
		size_t len;
		size_t realDataOffset = 0;
		if (!enc_iv_inited) {
			if (outData->Length < ivLen) throw ref new InvalidArgumentException(L"Not enough space for IV");
			// outData->Length >= ivLen
			memcpy_s(outData->Data, outData->Length, iv, ivLen);
			realDataOffset += ivLen;
			enc_iv_inited = true;
		}
		mbedtls_cipher_update(encctx, encData->begin(), encData->Length, outData->begin() + realDataOffset, &len);
		return len + realDataOffset;
	}
	size_t MbedStreamCryptor::Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData)
	{
		auto realDecData = decData->begin();
		auto realLen = decDataLen;
		if (!dec_iv_inited) {
			if (decData->Length < ivLen) throw ref new InvalidArgumentException(L"IV not enough");
			mbedtls_cipher_set_iv(decctx, decData->begin(), ivLen);
			realDecData += ivLen;
			realLen -= ivLen;
			dec_iv_inited = true;
		}
		size_t len;
		mbedtls_cipher_update(decctx, realDecData, realLen, outData->begin(), &len);
		return len;
	}
	MbedStreamCryptor::~MbedStreamCryptor()
	{
		mbedtls_cipher_free(encctx);
		mbedtls_cipher_free(decctx);
		free(iv);
	}
}
