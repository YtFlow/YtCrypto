#pragma once
#include "MbedCryptor.g.h"
#include "mbedtls\cipher.h"
#include "Common.h"

namespace winrt::YtCrypto::implementation
{
    struct MbedCryptor : MbedCryptorT<MbedCryptor>
    {
    private:
        mbedtls_cipher_context_t encctx;
        mbedtls_cipher_context_t decctx;
        bool enc_iv_inited = false;
        bool dec_iv_inited = false;
        size_t keyLen;
        int ivLen;
        std::unique_ptr<uint8_t[]> iv;
        std::shared_ptr<uint8_t[]> key;
        std::array<uint8_t, 12> encNonce = { 0 };
        std::array<uint8_t, 12> decNonce = { 0 };
        int Encrypt(const uint8_t* encData, int encDataLen, uint8_t* outData, int outDataLen);
        int Decrypt(const uint8_t* decData, int decDataLen, uint8_t* outData, int outDataLen);
        int EncryptAuth(const uint8_t* encData, int encDataLen, uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen);
        int DecryptAuth(const uint8_t* decData, int decDataLen, const uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen);
    public:
        MbedCryptor(std::shared_ptr<uint8_t[]> key, size_t keyLen, std::unique_ptr<uint8_t[]> iv, int ivLen, mbedtls_cipher_type_t cipher_type);

        uint64_t IvLen();
        uint32_t Encrypt(array_view<uint8_t const> encData, uint32_t encDataLen, array_view<uint8_t> outData);
        uint32_t Encrypt(uint64_t encData, uint32_t encDataLen, uint64_t outData, uint32_t outDataLen);
        uint32_t Decrypt(array_view<uint8_t const> decData, uint32_t decDataLen, array_view<uint8_t> outData);
        uint32_t Decrypt(uint64_t decData, uint32_t decDataLen, uint64_t outData, uint32_t outDataLen);
        int32_t EncryptAuth(uint64_t encData, uint32_t encDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen);
        int32_t DecryptAuth(uint64_t decData, uint32_t decDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen);

        virtual ~MbedCryptor() noexcept;
    };
}
