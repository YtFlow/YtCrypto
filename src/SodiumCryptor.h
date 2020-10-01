#pragma once
#include "SodiumCryptor.g.h"
#include "crypto_stream_salsa20.h"
#include "crypto_stream_chacha20.h"
#include "crypto_aead_chacha20poly1305.h"
#include "crypto_aead_xchacha20poly1305.h"
#include "Algorithm.h"
#include "Common.h"
#include "AeadMixin.h"

using namespace YtCrypto;

namespace winrt::YtCrypto::implementation
{
    template <mbedtls_cipher_type_t CipherType>
    constexpr bool IsSodiumAead() {
        return CipherType == Algorithm::Chacha20Poly1305
            || CipherType == Algorithm::XChacha20Poly1305;
    }

    template<bool IsAead>
    struct SodiumStreamMixin { };

    template<>
    struct SodiumStreamMixin<false>
    {
        uint64_t encCounter = 0ul;
        uint64_t decCounter = 0ul;
    };

    template <mbedtls_cipher_type_t CipherType, int KeyLen, int IvSize, int NonceSize = 0, int TagSize = 0, bool IsAead = IsSodiumAead<CipherType>()>
    struct SodiumCryptor
        : SodiumCryptorT<SodiumCryptor<CipherType, KeyLen, IvSize, NonceSize, TagSize>>,
        public AeadMixin<NonceSize, TagSize>, public SodiumStreamMixin<IsAead>
    {
    private:
        static const inline Algorithm algorithm = static_cast<Algorithm>(CipherType);
        static const inline size_t SODIUM_BLOCK_SIZE = 64;
        bool enc_iv_inited = false;
        bool dec_iv_inited = false;
        std::array<uint8_t, IvSize> encIv;
        std::array<uint8_t, IvSize> decIv;
        std::array<uint8_t, KeyLen> encKey;
        std::array<uint8_t, KeyLen> decKey;
        std::shared_ptr<std::array<uint8_t, KeyLen>> key;
        std::vector<uint8_t> encBuf{};
        std::vector<uint8_t> decBuf{};
        int Encrypt(const uint8_t* encData, int encDataLen, uint8_t* outData, int outDataLen)
        {
            if constexpr (IsAead) {
                throw hresult_not_implemented(L"Called enc on AEAD methods");
            }
            else {
                int realDataOffset = 0;
                if (!enc_iv_inited) {
                    enc_iv_inited = true;
                    if (outDataLen - encDataLen < IvSize) {
                        throw hresult_invalid_argument(L"Not enough space for IV");
                    }
                    // outData->Length >= IvSize
                    if (memcpy_s(outData, outDataLen, encIv.data(), IvSize)) {
                        throw hresult_out_of_bounds(L"Cannot copy iv to outData");
                    }
                    realDataOffset += IvSize;
                }

                auto padding = (size_t)(encCounter % SODIUM_BLOCK_SIZE);
                auto inputBuf = encData;
                auto outputBuf = outData + realDataOffset;
                auto inputSize = encDataLen;
                if (padding > 0) {
                    encBuf.resize(padding + encDataLen);
                    mbedtls_platform_zeroize(encBuf.data(), padding);
                    if (memcpy_s(encBuf.data() + padding, encDataLen, encData, encDataLen)) {
                        throw hresult_out_of_bounds(L"Cannot move data after padding");
                    }
                    inputBuf = outputBuf = encBuf.data();
                    inputSize = (int)encBuf.size();
                }

                if constexpr (algorithm == Algorithm::Salsa20) {
                    crypto_stream_salsa20_xor_ic(outputBuf, inputBuf, inputSize, encIv.data(), encCounter / SODIUM_BLOCK_SIZE, (*key).data());
                }
                else if constexpr (algorithm == Algorithm::Chacha20) {
                    crypto_stream_chacha20_xor_ic(outputBuf, inputBuf, inputSize, encIv.data(), encCounter / SODIUM_BLOCK_SIZE, (*key).data());
                }
                else {
                    throw hresult_not_implemented(L"Unsupported cipher");
                }

                if (padding > 0) {
                    if (memcpy_s(outData + realDataOffset, outDataLen - realDataOffset, encBuf.data() + padding, encBuf.size() - padding)) {
                        throw hresult_out_of_bounds(L"Cannot copy out data");
                    }
                }
                encCounter += encDataLen;
                return encDataLen + realDataOffset;
            }
        }
        int Decrypt(const uint8_t* decData, int decDataLen, uint8_t* outData, int outDataLen)
        {
            if constexpr (IsAead) {
                throw hresult_not_implemented(L"Called dec on AEAD methods");
            }
            else {
                auto realDecData = decData;
                auto realLen = decDataLen;
                if (!dec_iv_inited) {
                    if (decDataLen < IvSize) {
                        throw hresult_invalid_argument(L"IV not enough");
                    }
                    dec_iv_inited = true;
                    decIv = std::array<uint8_t, IvSize>{};
                    if (memcpy_s(decIv.data(), IvSize, decData, IvSize)) {
                        throw hresult_out_of_bounds(L"Cannot get iv");
                    }
                    realDecData += IvSize;
                    realLen -= IvSize;
                    if (realLen == 0) {
                        return 0;
                    }
                }

                int padding = (int)(decCounter % SODIUM_BLOCK_SIZE);
                auto inputBuf = realDecData;
                auto outputBuf = outData;
                auto inputSize = realLen;
                if (padding > 0) {
                    decBuf.resize(padding + realLen);
                    mbedtls_platform_zeroize(decBuf.data(), padding);
                    if (memcpy_s(decBuf.data() + padding, realLen, realDecData, realLen)) {
                        throw hresult_out_of_bounds(L"Cannot move data after padding");
                    }
                    inputBuf = outputBuf = decBuf.data();
                    inputSize = (int)decBuf.size();
                }

                if constexpr (algorithm == Algorithm::Salsa20) {
                    crypto_stream_salsa20_xor_ic(outputBuf, inputBuf, inputSize, decIv.data(), decCounter / SODIUM_BLOCK_SIZE, (*key).data());
                }
                else if constexpr (algorithm == Algorithm::Chacha20) {
                    crypto_stream_chacha20_xor_ic(outputBuf, inputBuf, inputSize, decIv.data(), decCounter / SODIUM_BLOCK_SIZE, (*key).data());
                }
                else {
                    throw hresult_not_implemented(L"Unsupported cipher");
                }

                if (padding > 0) {
                    if (memcpy_s(outData, outDataLen, decBuf.data() + padding, decBuf.size() - padding)) {
                        throw hresult_out_of_bounds(L"Cannot copy out data");
                    }
                }
                decCounter += realLen;
                return realLen;
            }
        }
        int EncryptAuth(const uint8_t* encData, int encDataLen, uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen)
        {
            if constexpr (IsAead) {
                if (!enc_iv_inited && outDataLen - IvSize < encDataLen || outDataLen < encDataLen) {
                    throw hresult_invalid_argument(L"outDataSize too small");
                }
                uint8_t* realOutData = outData;
                if (!enc_iv_inited) {
                    enc_iv_inited = true;
                    if (memcpy_s(outData, outDataLen, encIv.data(), IvSize)) {
                        throw hresult_out_of_bounds(L"Cannot copy iv to outData");
                    }
                    realOutData += IvSize;
                    if (encDataLen == 0) {
                        return IvSize;
                    }
                    outDataLen -= IvSize;
                }
                uint64_t tagSize;
                int ret;

                if constexpr (algorithm == Algorithm::Chacha20Poly1305) {
                    ret = crypto_aead_chacha20poly1305_encrypt_detached(realOutData, tagData, &tagSize, encData, encDataLen, NULL, 0, NULL, encNonce.data(), encKey.data());
                }
                else if constexpr (algorithm == Algorithm::XChacha20Poly1305) {
                    ret = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(realOutData, tagData, &tagSize, encData, encDataLen, NULL, 0, NULL, encNonce.data(), encKey.data());
                }
                else {
                    throw hresult_not_implemented(L"Unsupported cipher");
                }

                if (tagSize != 16) {
                    throw hresult_invalid_argument(L"Unexpected tag size: " + std::to_wstring(tagSize));
                }
                if (ret != 0) {
                    return ret;
                }
                sodium_increment(encNonce.data(), NonceSize);
                return (int)(realOutData - outData) + encDataLen;

            }
            else {
                throw hresult_not_implemented(L"Called enc auth on non-AEAD methods");
            }
        }
        int DecryptAuth(const uint8_t* decData, int decDataLen, const uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen)
        {
            if constexpr (IsAead) {
                if (!dec_iv_inited && outDataLen < decDataLen - IvSize || dec_iv_inited && outDataLen < decDataLen) {
                    throw hresult_invalid_argument(L"outDataSize too small");
                }
                if (!dec_iv_inited) {
                    if (decDataLen < IvSize) {
                        throw hresult_invalid_argument(L"IV not enough");
                    }
                    dec_iv_inited = true;
                    decKey = std::array<uint8_t, KeyLen>{};
                    auto ret = Common::DeriveAuthSessionKeySha1<KeyLen>(decData, IvSize, *key, decKey.data(), KeyLen);
                    if (ret != 0) {
                        throw hresult_invalid_argument(L"Cannot derive dec session key, Mbed TLS returned: " + std::to_wstring(ret));
                    }
                    decIv = std::array<uint8_t, IvSize>{};
                    if (memcpy_s(decIv.data(), IvSize, decData, IvSize)) {
                        throw hresult_out_of_bounds(L"Cannot get iv");
                    }
                    decData += IvSize;
                    decDataLen -= IvSize;
                    if (decDataLen == 0) {
                        return 0;
                    }
                }
                int ret;

                if constexpr (algorithm == Algorithm::Chacha20Poly1305) {
                    ret = crypto_aead_chacha20poly1305_decrypt_detached(outData, NULL, decData, decDataLen, tagData, NULL, 0, decNonce.data(), decKey.data());
                }
                else if constexpr (algorithm == Algorithm::XChacha20Poly1305) {
                    ret = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(outData, NULL, decData, decDataLen, tagData, NULL, 0, decNonce.data(), decKey.data());
                }
                else {
                    throw hresult_not_implemented(L"Unsupported cipher");
                }

                if (ret != 0) {
                    return ret;
                }
                sodium_increment(decNonce.data(), NonceSize);
                return decDataLen;
            }
            else {
                throw hresult_not_implemented(L"Called dec auth on non-AEAD methods");
            }
        }

    public:
        SodiumCryptor(std::shared_ptr<std::array<uint8_t, KeyLen>> key, std::array<uint8_t, IvSize> iv)
            : key(key), encIv(iv)
        {
            if constexpr (IsAead) {
                auto ret = Common::DeriveAuthSessionKeySha1<KeyLen>(encIv.data(), IvSize, *key, encKey.data(), KeyLen);
                if (ret != 0) {
                    throw hresult_invalid_argument(L"Cannot derive enc session key, Mbed TLS returned: " + std::to_wstring(ret));
                }
            }
        }
        uint64_t IvLen()
        {
            return IvSize;
        }
        uint32_t Encrypt(array_view<uint8_t const> encData, uint32_t encDataLen, array_view<uint8_t> outData)
        {
            return Encrypt(encData.data(), (uint32_t)encData.size(), outData.data(), (uint32_t)outData.size());
        }
        uint32_t Encrypt(uint64_t encData, uint32_t encDataLen, uint64_t outData, uint32_t outDataLen)
        {
            return Encrypt((const uint8_t*)encData, (uint32_t)encDataLen, (uint8_t*)outData, (uint32_t)outDataLen);
        }
        uint32_t Decrypt(array_view<uint8_t const> decData, uint32_t decDataLen, array_view<uint8_t> outData)
        {
            return Decrypt(decData.data(), (uint32_t)decData.size(), outData.data(), (uint32_t)outData.size());
        }
        uint32_t Decrypt(uint64_t decData, uint32_t decDataLen, uint64_t outData, uint32_t outDataLen)
        {
            return Decrypt((const uint8_t*)decData, (uint32_t)decDataLen, (uint8_t*)outData, outDataLen);
        }
        int32_t EncryptAuth(uint64_t encData, uint32_t encDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen)
        {
            return EncryptAuth((const uint8_t*)encData, (uint32_t)encDataLen, (uint8_t*)tagData, (uint32_t)tagDataLen, (uint8_t*)outData, outDataLen);
        }
        int32_t DecryptAuth(uint64_t decData, uint32_t decDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen)
        {
            return DecryptAuth((const uint8_t*)decData, (uint32_t)decDataLen, (const uint8_t*)tagData, (uint32_t)tagDataLen, (uint8_t*)outData, outDataLen);
        }

        virtual ~SodiumCryptor() noexcept
        {
            mbedtls_platform_zeroize(encIv.data(), IvSize);
            mbedtls_platform_zeroize(decIv.data(), IvSize);
            if constexpr (IsAead) {
                mbedtls_platform_zeroize(encNonce.data(), NonceSize);
                mbedtls_platform_zeroize(decNonce.data(), NonceSize);
            } else {
                if (encBuf.size() > 0) {
                    mbedtls_platform_zeroize(encBuf.data(), encBuf.size());
                }
                if (decBuf.size() > 0) {
                    mbedtls_platform_zeroize(decBuf.data(), decBuf.size());
                }
            }
        }
    };
}
