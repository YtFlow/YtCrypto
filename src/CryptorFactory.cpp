#include "CryptorFactory.h"
#include "mbedtls/md5.h"
#include <cstdlib>
#include <cstring>
#include <Windows.h>
#include <bcrypt.h>

namespace YtCrypto {
	CipherInfo CryptorFactory::FindCipherInfo(std::wstring cipherName)
	{
		auto cipherIt = CipherInfo::Ciphers.find(cipherName);
		if (cipherIt == CipherInfo::Ciphers.end()) {
			throw ref new Platform::NotImplementedException(L"The given cipher is not supported yet");
		}
		return cipherIt->second;
	}

	ICryptor^ CryptorFactory::CreateCryptor() {
		std::unique_ptr<uint8> iv, salt;
		switch (cipherInfo.Provider) {
		case CryptorProvider::MbedtlsStream:
			iv = std::unique_ptr<uint8>(Common::GenerateIv(cipherInfo.IvLen));
			if (iv == nullptr) {
				throw ref new Platform::FailureException(L"Cannot generate IV");
			}
			return ref new MbedCryptor(key, cipherInfo.KeyLen, std::move(iv), cipherInfo.IvLen, cipherInfo.CipherType);
		case CryptorProvider::MbedtlsAuth:
			salt = std::unique_ptr<uint8>(Common::GenerateIv(cipherInfo.SaltLen));
			return ref new MbedCryptor(key, cipherInfo.KeyLen, std::move(salt), cipherInfo.SaltLen, cipherInfo.CipherType);
		default:
			throw ref new Platform::NotImplementedException(L"Cannot create a cryptor with an unknown provider");
		}
	}

	CryptorFactory::CryptorFactory(Platform::String^ method, const Platform::Array<uint8, 1>^ password)
		: cipherInfo(CryptorFactory::FindCipherInfo(std::wstring(method->Data()))) {
		// Derive key
		key = std::shared_ptr<uint8>(Common::LegacyDeriveKey(password->Data, password->Length, cipherInfo.KeyLen));
		if (key == nullptr) {
			throw ref new Platform::FailureException(L"Cannot derive key");
		}
	}

	CryptorFactory::~CryptorFactory()
	{
		// Key data are shared among all cryptor instances
		// free(key);
	}
}
