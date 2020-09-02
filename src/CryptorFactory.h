#pragma once
#include "CryptorFactory.g.h"
#include "CipherInfo.h"
#include "Common.h"
#include "MbedCryptor.h"
#include "SodiumCryptor.h"
#include "core.h"

using namespace YtCrypto;

namespace winrt::YtCrypto::implementation
{
    template <CryptorProvider Provider, mbedtls_cipher_type_t CipherType, int KeyLen, int IvLen, int NonceLen, int TagLen>
    struct CryptorFactory : CryptorFactoryT<CryptorFactory<Provider, CipherType, KeyLen, IvLen, NonceLen, TagLen>>
    {
    private:
        std::shared_ptr<std::array<uint8_t, KeyLen>> key;
    public:
        CryptorFactory(std::array<uint8_t, KeyLen> key) noexcept
            : key(std::make_shared<std::array<uint8_t, KeyLen>>(key)) {
            if constexpr (Provider == CryptorProvider::SodiumAuth
                || Provider == CryptorProvider::SodiumStream) {
                sodium_init();
            }
        }
        static YtCrypto::CryptorFactory CreateFactory(hstring const& method, array_view<uint8_t const> password) {
            auto cipherInfoIt = CipherInfo::Ciphers.find(method);
            if (cipherInfoIt == CipherInfo::Ciphers.end()) {
                throw hresult_invalid_argument(L"The given cipher is not supported yet").to_abi();
            }
            else {
                auto cipherInfoCreator = cipherInfoIt->second;
                return cipherInfoCreator(password);
            }
        }
        ICryptor CreateCryptor() {
            std::array<uint8_t, IvLen> iv{};
            if (!Common::GenerateIv(iv)) {
                // This cannot happen
                throw hresult_invalid_argument(L"Cannot generate IV").to_abi();
            }
            if constexpr (Provider == CryptorProvider::MbedtlsStream || Provider == CryptorProvider::MbedtlsAuth) {
                return winrt::make<winrt::YtCrypto::implementation::MbedCryptor<CipherType, KeyLen, IvLen, NonceLen, TagLen>>(key, iv);
            }
            if constexpr (Provider == CryptorProvider::SodiumStream || Provider == CryptorProvider::SodiumAuth) {
                return winrt::make<winrt::YtCrypto::implementation::SodiumCryptor<CipherType, KeyLen, IvLen, NonceLen, TagLen>>(key, iv);
            }
            throw hresult_not_implemented(L"Unknown cryptor privider").to_abi();
        }
    };
}
namespace winrt::YtCrypto::factory_implementation
{
    struct CryptorFactory : CryptorFactoryT<CryptorFactory, implementation::CryptorFactory<CryptorProvider::MbedtlsAuth,MBEDTLS_CIPHER_ARIA_256_GCM, 16, 16, 16, 16>>
    {
    };
}
