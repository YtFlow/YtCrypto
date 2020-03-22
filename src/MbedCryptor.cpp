#include "pch.h"
#include "MbedCryptor.h"
#include "MbedCryptor.g.cpp"

namespace winrt::YtCrypto::implementation
{
    int MbedCryptor::Encrypt(const uint8_t* encData, int encDataLen, uint8_t* outData, int outDataLen)
    {
        size_t len, realDataOffset = 0;
        if (!enc_iv_inited) {
            enc_iv_inited = true;
            if (outDataLen - encDataLen < ivLen) {
                throw hresult_invalid_argument(L"Not enough space for IV");
            }
            // outData->Length >= ivLen
            if (memcpy_s(outData, outDataLen, iv.get(), ivLen)) {
                throw hresult_out_of_bounds(L"Cannot copy iv to outData");
            }
            realDataOffset += ivLen;
        }
        mbedtls_cipher_update(&encctx, encData, encDataLen, outData + realDataOffset, &len);
        return (int)(len + realDataOffset);
    }
    int MbedCryptor::Decrypt(const uint8_t* decData, int decDataLen, uint8_t* outData, int outDataLen)
    {
        auto realDecData = decData;
        auto realLen = decDataLen;
        if (!dec_iv_inited) {
            if (decDataLen < ivLen) {
                throw hresult_invalid_argument(L"IV not enough");
            }
            dec_iv_inited = true;
            mbedtls_cipher_set_iv(&decctx, decData, ivLen);
            if (decctx.cipher_info->type == MBEDTLS_CIPHER_ARC4_128) {
                std::array<uint8_t, MD5_LEN> realDecKey;
                if (!Common::GenerateKeyMd5(key.get(), keyLen, decData, ivLen, realDecKey.data())) {
                    // This cannot happen unless there is something wrong with Mbed TLS
                    throw L"Cannot derive dec key using md5";
                }
                mbedtls_cipher_setkey(&decctx, realDecKey.data(), 8 * (int)keyLen, MBEDTLS_DECRYPT);
                mbedtls_platform_zeroize(realDecKey.data(), realDecKey.size());
            }
            realDecData += ivLen;
            realLen -= ivLen;
            if (realLen == 0) {
                return 0;
            }
        }
        size_t len;
        mbedtls_cipher_update(&decctx, realDecData, realLen, outData, &len);
        return (int)len;
    }
    int MbedCryptor::EncryptAuth(const uint8_t* encData, int encDataLen, uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen)
    {
        if (!enc_iv_inited && outDataLen - ivLen < encDataLen || outDataLen < encDataLen) {
            throw hresult_invalid_argument(L"outDataSize too small");
		}
        if (!enc_iv_inited) {
            enc_iv_inited = true;
            if (memcpy_s(outData, outDataLen, iv.get(), ivLen)) {
                throw hresult_out_of_bounds(L"Cannot copy iv to outData");
            }
            outData += ivLen;
            if (encDataLen == 0) {
                return ivLen;
            }
            outDataLen -= ivLen;
        }
        size_t size;
        auto ret = mbedtls_cipher_auth_encrypt(&encctx, encNonce.data(), encNonce.size(), nullptr, 0, encData, encDataLen, outData, &size, tagData, tagDataSize);
        if (ret != 0) {
            return ret;
        }
        sodium_increment(encNonce.data(), encNonce.size());
        return (int)size;
    }
    int MbedCryptor::DecryptAuth(const uint8_t* decData, int decDataLen, const uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen)
    {
        if (!dec_iv_inited && outDataLen < decDataLen - ivLen || dec_iv_inited && outDataLen < decDataLen) {
            throw hresult_invalid_argument(L"outDataSize too small");
        }
        if (!dec_iv_inited) {
            if (decDataLen < ivLen) {
                throw hresult_invalid_argument(L"IV not enough");
            }
            dec_iv_inited = true;
            auto sessionKey = std::make_unique<uint8_t[]>(keyLen);
            auto ret = Common::DeriveAuthSessionKeySha1(decData, ivLen, key.get(), keyLen, sessionKey.get(), keyLen);
            if (ret != 0) {
                throw hresult_invalid_argument(L"Cannot derive dec session key, Mbed TLS returned: " + std::to_wstring(ret));
            }
            mbedtls_cipher_setkey(&decctx, sessionKey.get(), 8 * (int)keyLen, MBEDTLS_DECRYPT);
            mbedtls_cipher_set_iv(&decctx, decData, ivLen);
            decData += ivLen;
            decDataLen -= ivLen;
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
    }
    MbedCryptor::MbedCryptor(std::shared_ptr<uint8_t[]> key, size_t keyLen, std::unique_ptr<uint8_t[]> iv, int ivLen, mbedtls_cipher_type_t cipher_type)
		: key(key), iv(std::move(iv)), keyLen(keyLen), ivLen(ivLen)
    {
        mbedtls_cipher_init(&encctx);
        mbedtls_cipher_init(&decctx);
        mbedtls_cipher_setup(&encctx, mbedtls_cipher_info_from_type(cipher_type));
        mbedtls_cipher_setup(&decctx, mbedtls_cipher_info_from_type(cipher_type));

        if (encctx.cipher_info->mode == MBEDTLS_MODE_GCM || encctx.cipher_info->mode == MBEDTLS_MODE_CHACHAPOLY) {
            auto sessionKey = std::make_unique<uint8_t[]>(keyLen);
            auto ret = Common::DeriveAuthSessionKeySha1(this->iv.get(), ivLen, key.get(), keyLen, sessionKey.get(), keyLen);
            if (ret != 0) {
                throw hresult_invalid_argument(L"Cannot derive enc session key, Mbed TLS returned: " + std::to_wstring(ret));
            }
            mbedtls_cipher_setkey(&encctx, sessionKey.get(), 8 * (int)keyLen, MBEDTLS_ENCRYPT);
            mbedtls_platform_zeroize(sessionKey.get(), keyLen);
        }
        else if (cipher_type == mbedtls_cipher_type_t::MBEDTLS_CIPHER_ARC4_128) {
            std::array<uint8_t, MD5_LEN> realEncKey;
            if (!Common::GenerateKeyMd5(key.get(), keyLen, this->iv.get(), ivLen, realEncKey.data())) {
                // This cannot happen unless there is something wrong with Mbed TLS
                throw L"Cannot derive enc key using md5";
            }
            mbedtls_cipher_setkey(&encctx, realEncKey.data(), 8 * (int)keyLen, MBEDTLS_ENCRYPT);
            mbedtls_platform_zeroize(realEncKey.data(), realEncKey.size());
        }
        else {
            mbedtls_cipher_setkey(&encctx, key.get(), 8 * (int)keyLen, MBEDTLS_ENCRYPT);
            mbedtls_cipher_setkey(&decctx, key.get(), 8 * (int)keyLen, MBEDTLS_DECRYPT);
        }
        mbedtls_cipher_set_iv(&encctx, this->iv.get(), ivLen);
    }
    uint64_t MbedCryptor::IvLen()
    {
        return ivLen;
    }
    uint32_t MbedCryptor::Encrypt(array_view<uint8_t const> encData, uint32_t encDataLen, array_view<uint8_t> outData)
    {
        return Encrypt(encData.data(), (uint32_t)encData.size(), outData.data(), (uint32_t)outData.size());
    }
    uint32_t MbedCryptor::Encrypt(uint64_t encData, uint32_t encDataLen, uint64_t outData, uint32_t outDataLen)
    {
        return Encrypt((const uint8_t*)encData, (uint32_t)encDataLen, (uint8_t*)outData, (uint32_t)outDataLen);
    }
    uint32_t MbedCryptor::Decrypt(array_view<uint8_t const> decData, uint32_t decDataLen, array_view<uint8_t> outData)
    {
        return Decrypt(decData.data(), (uint32_t)decData.size(), outData.data(), (uint32_t)outData.size());
    }
    uint32_t MbedCryptor::Decrypt(uint64_t decData, uint32_t decDataLen, uint64_t outData, uint32_t outDataLen)
    {
        return Decrypt((const uint8_t*)decData, (uint32_t)decDataLen, (uint8_t*)outData, outDataLen);
    }
    int32_t MbedCryptor::EncryptAuth(uint64_t encData, uint32_t encDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen)
    {
        return EncryptAuth((const uint8_t*)encData, (uint32_t)encDataLen, (uint8_t*)tagData, (uint32_t)tagDataLen, (uint8_t*)outData, outDataLen);
    }
    int32_t MbedCryptor::DecryptAuth(uint64_t decData, uint32_t decDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen)
    {
        return DecryptAuth((const uint8_t*)decData, (uint32_t)decDataLen, (const uint8_t*)tagData, (uint32_t)tagDataLen, (uint8_t*)outData, outDataLen);
    }
    MbedCryptor::~MbedCryptor()
    {
		if (encctx.cipher_info->mode == MBEDTLS_MODE_GCM || encctx.cipher_info->mode == MBEDTLS_MODE_CHACHAPOLY) {
			mbedtls_platform_zeroize(encNonce.data(), encNonce.size());
			mbedtls_platform_zeroize(decNonce.data(), decNonce.size());
		}
		mbedtls_cipher_free(&encctx);
		mbedtls_cipher_free(&decctx);
		mbedtls_platform_zeroize(iv.get(), ivLen);
    }
}
