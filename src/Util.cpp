#include "pch.h"
#include "Util.h"
#include "Util.g.cpp"

namespace winrt::YtCrypto::implementation
{
    void Util::Sha224(array_view<uint8_t const> key, array_view<uint8_t> outBuf)
    {
        if (outBuf.size() < 32) {
            throw hresult_invalid_argument(L"SSH224 must have an output buffer of at least 32 bytes").to_abi();;
        }
        auto ret = mbedtls_sha256_ret(key.data(), key.size(), outBuf.data(), 1);
        if (ret != 0) {
            // This cannot happen
            throw L"Cannot calculate sha224, Mbed TLS returned: " + std::to_wstring(ret);
        }
    }
}
