#pragma once
#include "mbedtls\cipher.h"
#include "ICryptor.h"

namespace WFM = Windows::Foundation::Metadata;

namespace YtCrypto
{
	public ref class MbedStreamCryptor sealed : [WFM::DefaultAttribute] ICryptor
	{
	private:
		mbedtls_cipher_context_t* encctx;
		mbedtls_cipher_context_t* decctx;
		bool enc_iv_inited;
		bool dec_iv_inited;
		size_t ivLen;
		uint8 *iv;
		uint8 *key;
	internal:
		MbedStreamCryptor(uint8 *key, size_t keyBitLen, uint8 *iv, size_t ivLen, mbedtls_cipher_type_t cipher_type);
	public:
		virtual size_t Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		virtual size_t Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		virtual ~MbedStreamCryptor();
	};
}
