#pragma once
#include <memory>
#include "mbedtls\cipher.h"
#include "ICryptor.h"
#include "Common.h"

namespace WFM = Windows::Foundation::Metadata;

namespace YtCrypto
{
	public ref class MbedStreamCryptor sealed : [WFM::DefaultAttribute] ICryptor
	{
	private:
		mbedtls_cipher_context_t encctx;
		mbedtls_cipher_context_t decctx;
		bool enc_iv_inited;
		bool dec_iv_inited;
		size_t keyLen;
		size_t ivLen;
		std::unique_ptr<uint8> iv;
		std::shared_ptr<uint8> key;
		size_t Encrypt(uint8* encData, size_t encDataLen, uint8* outData, size_t outDataLen);
		size_t Decrypt(uint8* decData, size_t decDataLen, uint8* outData, size_t outDataLen);
	internal:
		MbedStreamCryptor(std::shared_ptr<uint8> key, size_t keyLen, std::unique_ptr<uint8> iv, size_t ivLen, mbedtls_cipher_type_t cipher_type);
	public:
		virtual size_t Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		virtual size_t Encrypt(IntPtrAbi encData, size_t encDataLen, IntPtrAbi outData, size_t outDataLen);
		virtual size_t Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		virtual size_t Decrypt(IntPtrAbi decData, size_t decDataLen, IntPtrAbi outData, size_t outDataLen);
		virtual ~MbedStreamCryptor();
	};
}
