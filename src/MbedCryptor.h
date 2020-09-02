#pragma once
#include "MbedCryptor.g.h"
#include "mbedtls\cipher.h"
#include "Common.h"
#include "AeadMixin.h"

namespace winrt::YtCrypto::implementation
{
    template <mbedtls_cipher_type_t CipherType>
    constexpr bool IsMbedAead() {
        return
            CipherType == MBEDTLS_CIPHER_AES_128_GCM
            || CipherType == MBEDTLS_CIPHER_AES_192_GCM
            || CipherType == MBEDTLS_CIPHER_AES_256_GCM
            || CipherType == MBEDTLS_CIPHER_CHACHA20_POLY1305;
    }

    template <mbedtls_cipher_type_t CipherType, int KeyLen, int IvSize, int NonceSize = 0, int TagSize = 0, bool IsAead = IsMbedAead<CipherType>()>
    struct MbedCryptor : MbedCryptorT<MbedCryptor<CipherType, KeyLen, IvSize, NonceSize, TagSize>>, public AeadMixin<NonceSize, TagSize>
    {
    private:
        mbedtls_cipher_context_t encctx;
        mbedtls_cipher_context_t decctx;
        bool enc_iv_inited = false;
        bool dec_iv_inited = false;
        std::shared_ptr<std::array<uint8_t, KeyLen>> key;
        std::array<uint8_t, IvSize> iv{};
        int Encrypt(const uint8_t* encData, int encDataLen, uint8_t* outData, int outDataLen)
        {
            size_t len, realDataOffset = 0;
            if (!enc_iv_inited) {
                enc_iv_inited = true;
                if (outDataLen - encDataLen < IvSize) {
                    throw hresult_invalid_argument(L"Not enough space for IV");
                }
                // outData->Length >= ivLen
                if (memcpy_s(outData, outDataLen, iv.data(), IvSize)) {
                    throw hresult_out_of_bounds(L"Cannot copy iv to outData");
                }
                realDataOffset += IvSize;
            }
            mbedtls_cipher_update(&encctx, encData, encDataLen, outData + realDataOffset, &len);
            return (int)(len + realDataOffset);
        }
        int Decrypt(const uint8_t* decData, int decDataLen, uint8_t* outData, int outDataLen)
        {
            auto realDecData = decData;
            auto realLen = decDataLen;
            if (!dec_iv_inited) {
                if (decDataLen < IvSize) {
                    throw hresult_invalid_argument(L"IV not enough");
                }
                dec_iv_inited = true;
                mbedtls_cipher_set_iv(&decctx, decData, IvSize);
                if (decctx.cipher_info->type == MBEDTLS_CIPHER_ARC4_128) {
                    std::array<uint8_t, MD5_LEN> realDecKey;
                    if (!Common::GenerateKeyMd5<KeyLen, IvSize>(*key, decData, realDecKey)) {
                        // This cannot happen unless there is something wrong with Mbed TLS
                        throw L"Cannot derive dec key using md5";
                    }
                    mbedtls_cipher_setkey(&decctx, realDecKey.data(), 8 * KeyLen, MBEDTLS_DECRYPT);
                    mbedtls_platform_zeroize(realDecKey.data(), realDecKey.size());
                }
                realDecData += IvSize;
                realLen -= IvSize;
                if (realLen == 0) {
                    return 0;
                }
            }
            size_t len;
            mbedtls_cipher_update(&decctx, realDecData, realLen, outData, &len);
            return (int)len;
        }
        int EncryptAuth(const uint8_t* encData, int encDataLen, uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen)
        {
            if constexpr (IsAead) {
                if (!enc_iv_inited && outDataLen - IvSize < encDataLen || outDataLen < encDataLen) {
                    throw hresult_invalid_argument(L"outDataSize too small");
                }
                if (!enc_iv_inited) {
                    enc_iv_inited = true;
                    if (memcpy_s(outData, outDataLen, iv.data(), IvSize)) {
                        throw hresult_out_of_bounds(L"Cannot copy iv to outData");
                    }
                    outData += IvSize;
                    if (encDataLen == 0) {
                        return IvSize;
                    }
                    outDataLen -= IvSize;
                }
                size_t size;
                auto ret = mbedtls_cipher_auth_encrypt(&encctx, encNonce.data(), encNonce.size(), nullptr, 0, encData, encDataLen, outData, &size, tagData, tagDataSize);
                if (ret != 0) {
                    return ret;
                }
                sodium_increment(encNonce.data(), encNonce.size());
                return (int)size;
            } else {
                throw hresult_not_implemented(L"Call enc auth on non-AEAD methods");
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
                    auto sessionKey = std::array<uint8_t, KeyLen>{};
                    auto ret = Common::DeriveAuthSessionKeySha1<KeyLen>(decData, IvSize, *key, sessionKey.data(), KeyLen);
                    if (ret != 0) {
                        throw hresult_invalid_argument(L"Cannot derive dec session key, Mbed TLS returned: " + std::to_wstring(ret));
                    }
                    mbedtls_cipher_setkey(&decctx, sessionKey.data(), 8 * KeyLen, MBEDTLS_DECRYPT);
                    mbedtls_cipher_set_iv(&decctx, decData, IvSize);
                    decData += IvSize;
                    decDataLen -= IvSize;
                    if (decDataLen == 0) {
                        return 0;
                    }
                }
                size_t size;
                auto ret = mbedtls_cipher_auth_decrypt(&decctx, decNonce.data(), decNonce.size(), nullptr, 0, decData, decDataLen, outData, &size, tagData, tagDataSize);
                if (ret != 0) {
                    return ret;
                }
                sodium_increment(decNonce.data(), decNonce.size());
                return (int)size;
            } else {
                throw hresult_not_implemented(L"Called dec auth on non-AEAD methods");
            }
        }

    public:
        MbedCryptor(std::shared_ptr<std::array<uint8_t, KeyLen>> key, std::array<uint8_t, IvSize> iv)
            : key(key), iv(iv)
        {
            mbedtls_cipher_init(&encctx);
            mbedtls_cipher_init(&decctx);
            mbedtls_cipher_setup(&encctx, mbedtls_cipher_info_from_type(CipherType));
            mbedtls_cipher_setup(&decctx, mbedtls_cipher_info_from_type(CipherType));

            if constexpr (IsAead) {
                auto sessionKey = std::array<uint8_t, KeyLen>{};
                auto ret = Common::DeriveAuthSessionKeySha1<KeyLen>(iv.data(), IvSize, *key, sessionKey.data(), KeyLen);
                if (ret != 0) {
                    throw hresult_invalid_argument(L"Cannot derive enc session key, Mbed TLS returned: " + std::to_wstring(ret));
                }
                mbedtls_cipher_setkey(&encctx, sessionKey.data(), 8 * KeyLen, MBEDTLS_ENCRYPT);
                mbedtls_platform_zeroize(sessionKey.data(), KeyLen);
            }
            else if constexpr (CipherType == mbedtls_cipher_type_t::MBEDTLS_CIPHER_ARC4_128) {
                std::array<uint8_t, MD5_LEN> realEncKey;
                if (!Common::GenerateKeyMd5<KeyLen, IvSize>(*key, iv.data(), realEncKey)) {
                    // This cannot happen unless there is something wrong with Mbed TLS
                    throw L"Cannot derive enc key using md5";
                }
                mbedtls_cipher_setkey(&encctx, realEncKey.data(), 8 * KeyLen, MBEDTLS_ENCRYPT);
                mbedtls_platform_zeroize(realEncKey.data(), realEncKey.size());
            }
            else {
                mbedtls_cipher_setkey(&encctx, key->data(), 8 * KeyLen, MBEDTLS_ENCRYPT);
                mbedtls_cipher_setkey(&decctx, key->data(), 8 * KeyLen, MBEDTLS_DECRYPT);
            }
            mbedtls_cipher_set_iv(&encctx, iv.data(), iv.size());
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

        virtual ~MbedCryptor() noexcept
        {
            if constexpr (IsAead) {
                mbedtls_platform_zeroize(encNonce.data(), encNonce.size());
                mbedtls_platform_zeroize(decNonce.data(), decNonce.size());
            }
            mbedtls_cipher_free(&encctx);
            mbedtls_cipher_free(&decctx);
            mbedtls_platform_zeroize(iv.data(), iv.size());
        }
    };
}
