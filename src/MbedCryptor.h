#pragma once
#include <memory>
#include "mbedtls\cipher.h"
#include "ICryptor.h"
#include "Common.h"

namespace WFM = Windows::Foundation::Metadata;

namespace YtCrypto
{
	public ref class MbedCryptor sealed : [WFM::DefaultAttribute] ICryptor
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
		std::array<uint8, 12> encNonce;
		std::array<uint8, 12> decNonce;
		size_t Encrypt(uint8* encData, size_t encDataLen, uint8* outData, size_t outDataLen);
		size_t Decrypt(uint8* decData, size_t decDataLen, uint8* outData, size_t outDataLen);
		int EncryptAuth(uint8* encData, int encDataLen, uint8* tagData, size_t tagDataSize, uint8* outData, int outDataLen);
		int DecryptAuth(uint8* decData, int decDataLen, uint8* tagData, size_t tagDataSize, uint8* outData, int outDataLen);
	internal:
		MbedCryptor(std::shared_ptr<uint8> key, size_t keyLen, std::unique_ptr<uint8> iv, size_t ivLen, mbedtls_cipher_type_t cipher_type);
	public:
		virtual property uint64 IvLen { virtual uint64 get(); }
		virtual size_t Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		virtual size_t Encrypt(IntPtrAbi encData, size_t encDataLen, IntPtrAbi outData, size_t outDataLen);
		virtual size_t Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		virtual size_t Decrypt(IntPtrAbi decData, size_t decDataLen, IntPtrAbi outData, size_t outDataLen);
		virtual int EncryptAuth(IntPtrAbi encData, int encDataLen, IntPtrAbi tagData, size_t tagDataLen, IntPtrAbi outData, int outDataLen);
		virtual int DecryptAuth(IntPtrAbi decData, int decDataLen, IntPtrAbi tagData, size_t tagDataLen, IntPtrAbi outData, int outDataLen);
		virtual ~MbedCryptor();
	};
}
