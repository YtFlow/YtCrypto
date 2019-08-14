#pragma once
#include "ICryptor.h"
#include "MbedStreamCryptor.h"
#include "mbedtls\cipher.h"

constexpr size_t MD5_LEN = 16;
namespace YtCrypto {
	enum CryptorProvider {
		Mbedtls
	};
	public ref class CryptorFactory sealed
	{
	private:
		static uint8* LegacyDeriveKey(uint8* password, size_t passwordLen, size_t keyLen);
		static uint8* GenerateIv(size_t ivLen);
		CryptorProvider provider;
		uint8* key;
		size_t keyLen;
		size_t ivLen;
		mbedtls_cipher_type_t mbedtls_cipher_type;
	public:
		ICryptor^ CreateCryptor();
		CryptorFactory(Platform::String^ method, const Platform::Array<uint8, 1>^ password);
		virtual ~CryptorFactory();
	};
}
