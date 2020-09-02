#pragma once
#include "pch.h"
#include <unordered_map>
#include "mbedtls\cipher.h"
#include "crypto_stream_chacha20.h"
#include "crypto_stream_salsa20.h"
#include "crypto_aead_chacha20poly1305.h"
#include "crypto_aead_xchacha20poly1305.h"
#include "CryptorProvider.h"
#include "Algorithm.h"
#include "winrt\YtCrypto.h"
#include "Common.h"
#include "CryptorFactory.h"

namespace YtCrypto {
    typedef winrt::YtCrypto::CryptorFactory factory_creator_t(winrt::array_view<uint8_t const> password);
    class CipherInfo
    {
    private:
    public:
        template <CryptorProvider Provider, mbedtls_cipher_type_t CipherType, int KeyLen, int IvLen, int NonceLen = 0, int TagLen = 0>
        static winrt::YtCrypto::CryptorFactory FactoryCreator(winrt::array_view<uint8_t const> password) {
            auto key = winrt::YtCrypto::Common::LegacyDeriveKey<KeyLen>(password.data(), password.size());
            return winrt::make<winrt::YtCrypto::implementation::CryptorFactory<Provider, CipherType, KeyLen, IvLen, NonceLen, TagLen>>(key);
        }
        static std::unordered_map<winrt::hstring, factory_creator_t*> Ciphers;
    };
}

