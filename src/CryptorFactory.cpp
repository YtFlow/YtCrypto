#include "pch.h"
#include "CryptorFactory.h"
#include "CryptorFactory.g.cpp"

namespace winrt::YtCrypto::implementation
{
    CryptorFactory::CryptorFactory(std::shared_ptr<uint8_t[]> key, const CipherInfo& cipherInfo) noexcept
        : key(key), cipherInfo(cipherInfo)
    {
        if (cipherInfo.Provider == CryptorProvider::SodiumAuth
            || cipherInfo.Provider == CryptorProvider::SodiumStream) {
            sodium_init();
        }
    }
    YtCrypto::CryptorFactory CryptorFactory::CreateFactory(hstring const& method, array_view<uint8_t const> password)
    {
        auto cipherInfoIt = CipherInfo::Ciphers.find(method);
        if (cipherInfoIt == CipherInfo::Ciphers.end()) {
            throw hresult_invalid_argument(L"The given cipher is not supported yet").to_abi();
        }
        else {
            auto cipherInfo = cipherInfoIt->second;
            auto key = std::shared_ptr<uint8_t[]>(Common::LegacyDeriveKey(password.data(), password.size(), cipherInfo->KeyLen));
            return winrt::make<CryptorFactory>(key, *cipherInfo);
        }
    }
    ICryptor CryptorFactory::CreateCryptor()
    {
        auto iv = std::make_unique<uint8_t[]>(cipherInfo.IvLen);
        if (!Common::GenerateIv(iv.get(), cipherInfo.IvLen)) {
            // This cannot happen
            throw hresult_invalid_argument(L"Cannot generate IV").to_abi();
        }
        switch (cipherInfo.Provider) {
        case CryptorProvider::MbedtlsStream:
        case CryptorProvider::MbedtlsAuth:
            return winrt::make<winrt::YtCrypto::implementation::MbedCryptor>(key, cipherInfo.KeyLen, std::move(iv), cipherInfo.IvLen, cipherInfo.CipherType);
        case CryptorProvider::SodiumStream:
            return winrt::make<winrt::YtCrypto::implementation::SodiumCryptor>(key, cipherInfo.KeyLen, std::move(iv), cipherInfo.IvLen, cipherInfo.CipherType);
        case CryptorProvider::SodiumAuth:
            return winrt::make<winrt::YtCrypto::implementation::SodiumCryptor>(key, cipherInfo.KeyLen, std::move(iv), cipherInfo.IvLen, cipherInfo.NonceLen, cipherInfo.CipherType);
        default:
            throw hresult_not_implemented(L"Unknown cryptor privider").to_abi();
        }
    }
}
