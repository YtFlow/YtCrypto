#pragma once
#include <memory>
#include "CipherInfo.h"
#include "ICryptor.h"
#include "MbedCryptor.h"

namespace YtCrypto {
	public ref class CryptorFactory sealed
	{
	private:
		CipherInfo cipherInfo;
		std::shared_ptr<uint8> key;
		static CipherInfo FindCipherInfo(std::wstring cipherName);
	public:
		ICryptor^ CreateCryptor();
		CryptorFactory(Platform::String^ method, const Platform::Array<uint8, 1>^ password);
		virtual ~CryptorFactory();
	};
}
