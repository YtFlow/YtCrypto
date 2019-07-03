#pragma once
#include "mbedtls\cipher.h"

namespace YtCrypto
{
	public ref class Test sealed
	{
	private:
		mbedtls_cipher_context_t* encctx;
		mbedtls_cipher_context_t* decctx;
		bool dec_iv_inited;
	public:
		Test(const Platform::Array<uint8, 1u>^ key, const Platform::Array<uint8, 1u>^ iv);
		unsigned int Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		unsigned int Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		virtual ~Test();
	};
}
