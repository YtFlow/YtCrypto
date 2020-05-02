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
    struct CryptorFactory : CryptorFactoryT<CryptorFactory>
    {
    private:
		const CipherInfo& cipherInfo;
		std::shared_ptr<uint8_t[]> key;
    public:
        CryptorFactory(std::shared_ptr<uint8_t[]> key, const CipherInfo& cipherInfo) noexcept;
        static YtCrypto::CryptorFactory CreateFactory(hstring const& method, array_view<uint8_t const> password);
        ICryptor CreateCryptor();
    };
}
namespace winrt::YtCrypto::factory_implementation
{
    struct CryptorFactory : CryptorFactoryT<CryptorFactory, implementation::CryptorFactory>
    {
    };
}
