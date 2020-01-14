#pragma once
#include <memory>
#include "ICryptor.h"
#include "MbedStreamCryptor.h"

namespace YtCrypto {
	enum CryptorProvider {
		Mbedtls
	};
	public ref class CryptorFactory sealed
	{
	private:
		CryptorProvider provider;
		std::shared_ptr<uint8> key;
		size_t keyLen;
		size_t ivLen;
		mbedtls_cipher_type_t mbedtls_cipher_type;
	public:
		ICryptor^ CreateCryptor();
		CryptorFactory(Platform::String^ method, const Platform::Array<uint8, 1>^ password);
		virtual ~CryptorFactory();
	};
}
