#pragma once
#include "pch.h"
#include "mbedtls\md5.h"
#include "mbedtls\hkdf.h"
#include "mbedtls\md.h"
#include "utils.h"

namespace winrt::YtCrypto {
    const char SS_AEAD_INFO[10] = "ss-subkey";
    const size_t SS_AEAD_INFO_LEN = strlen(SS_AEAD_INFO);
    const size_t MD5_LEN = 16;
    const size_t SHA224_LEN = 32;
    struct Common
    {
        Common() = delete;

        // https://github.com/shadowsocks/shadowsocks-windows/blob/master/shadowsocks-csharp/Encryption/Stream/StreamEncryptor.cs#L71
        template <int KeyLen>
        static std::array<uint8_t, KeyLen> LegacyDeriveKey(const uint8_t* password, size_t passwordLen)
        {
            std::array<uint8_t, KeyLen> key;
            size_t resultLen = passwordLen + MD5_LEN;
            uint8_t* result = (uint8_t*)malloc(resultLen);
            if (result == NULL) {
                throw std::bad_alloc{};
            }
            size_t i = 0;
            uint8_t md5sum[MD5_LEN];
            while (i < KeyLen) {
                if (i == 0) {
                    if (mbedtls_md5_ret(password, passwordLen, md5sum)) goto ERR;
                }
                else {
                    // passwordLen + MD5_LEN >= MD5_LEN
                    if (memcpy_s(result, resultLen, md5sum, MD5_LEN)) goto ERR;
                    // passwordLen == passwordLen
                    if (memcpy_s(result + MD5_LEN, passwordLen, password, passwordLen)) goto ERR;
                    if (mbedtls_md5_ret(result, resultLen, md5sum)) goto ERR;
                }
                // keyLen - i >= min(MD5_LEN, keyLen - i)
                if (memcpy_s(&key[i], KeyLen - i, md5sum, min(MD5_LEN, KeyLen - i))) goto ERR;
                i += MD5_LEN;
            }
            free(result);
            return key;

    ERR:	
            free(result);
            throw std::bad_alloc{};

        }

        template <int IvLen>
        static bool GenerateIv(std::array<uint8_t, IvLen> &data) noexcept
        {
            return SUCCEEDED(BCryptGenRandom(nullptr, data.data(), (ULONG)IvLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
        }

        template <int KeyLen, int IvLen>
        static bool GenerateKeyMd5(const std::array<uint8_t, KeyLen> &key, const uint8_t *iv, std::array<uint8_t, MD5_LEN> &outBuf) noexcept
        {
            mbedtls_md5_context md5Ctx;
            mbedtls_md5_init(&md5Ctx);
            if (mbedtls_md5_starts_ret(&md5Ctx)) goto ERR;
            if (mbedtls_md5_update_ret(&md5Ctx, key.data(), KeyLen)) goto ERR;
            if (mbedtls_md5_update_ret(&md5Ctx, iv, IvLen)) goto ERR;
            if (mbedtls_md5_finish_ret(&md5Ctx, outBuf.data())) goto ERR;
            mbedtls_md5_free(&md5Ctx);
            return true;

        ERR:	
            mbedtls_md5_free(&md5Ctx);
            return false;
        }

        template <int MasterKeyLen>
        static int DeriveAuthSessionKeySha1(const uint8_t* salt, size_t saltLen, const std::array<uint8_t, MasterKeyLen> masterKey, uint8_t* sessionKey, size_t sessionKeyLen) noexcept
        {
            auto md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
            return mbedtls_hkdf(md, salt, saltLen, masterKey.data(), MasterKeyLen, (const unsigned char*)SS_AEAD_INFO, SS_AEAD_INFO_LEN, sessionKey, sessionKeyLen);
        }
    };
}

