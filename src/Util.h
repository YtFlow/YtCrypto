#pragma once
#include <memory>
#include "Util.g.h"
#include "mbedtls\md5.h"
#include "mbedtls\hkdf.h"
#include "mbedtls\md.h"
#include "mbedtls\sha256.h"
#include "utils.h"

namespace winrt::YtCrypto::implementation
{
    const char SS_AEAD_INFO[10] = "ss-subkey";
    const size_t SS_AEAD_INFO_LEN = strlen(SS_AEAD_INFO);
    const size_t MD5_LEN = 16;
    const size_t SHA224_LEN = 32;
    struct Util
    {
        Util() = default;

        static void Sha224(array_view<uint8_t const> key, array_view<uint8_t> outBuf);
    };
}
namespace winrt::YtCrypto::factory_implementation
{
    struct Util : UtilT<Util, implementation::Util>
    {
    };
}
