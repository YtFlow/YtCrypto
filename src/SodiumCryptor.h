#pragma once
#include "SodiumCryptor.g.h"
#include "crypto_stream_salsa20.h"
#include "crypto_stream_chacha20.h"
#include "crypto_aead_chacha20poly1305.h"
#include "crypto_aead_xchacha20poly1305.h"
#include "Algorithm.h"
#include "Common.h"

using namespace YtCrypto;

namespace winrt::YtCrypto::implementation
{
    struct SodiumCryptor : SodiumCryptorT<SodiumCryptor>
    {
    private:
        const size_t SODIUM_BLOCK_SIZE = 64;
        const size_t MAX_BLOCK_SIZE = 0x3FFF;
        Algorithm algorithm;
        bool enc_iv_inited = false;
        bool dec_iv_inited = false;
        size_t keyLen;
        int ivLen;
        size_t nonceLen;
        std::unique_ptr<uint8_t[]> encIv;
        std::unique_ptr<uint8_t[]> decIv;
        std::shared_ptr<uint8_t[]> encKey;
        std::shared_ptr<uint8_t[]> decKey;
        std::shared_ptr<uint8_t[]> key;
        std::vector<uint8_t> encBuf = {};
        std::vector<uint8_t> decBuf = {};
        // Cannot use fix-sized std::array here because
        // xchacha20-ietf-poly1305 uses a nonce of size 24
        std::unique_ptr<uint8_t[]> encNonce;
        std::unique_ptr<uint8_t[]> decNonce;
        uint64_t encCounter = 0ul;
        uint64_t decCounter = 0ul;
        int Encrypt(const uint8_t* encData, int encDataLen, uint8_t* outData, int outDataLen);
        int Decrypt(const uint8_t* decData, int decDataLen, uint8_t* outData, int outDataLen);
        int EncryptAuth(const uint8_t* encData, int encDataLen, uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen);
        int DecryptAuth(const uint8_t* decData, int decDataLen, const uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen);

    public:
        // Stream
        SodiumCryptor(std::shared_ptr<uint8_t[]> key, size_t keyLen, std::unique_ptr<uint8_t[]> iv, int ivLen, mbedtls_cipher_type_t cipher_type);
        // AEAD
        SodiumCryptor(std::shared_ptr<uint8_t[]> key, size_t keyLen, std::unique_ptr<uint8_t[]> iv, int ivLen, size_t nonceLen, mbedtls_cipher_type_t cipher_type);

        uint64_t IvLen();
        uint32_t Encrypt(array_view<uint8_t const> encData, uint32_t encDataLen, array_view<uint8_t> outData);
        uint32_t Encrypt(uint64_t encData, uint32_t encDataLen, uint64_t outData, uint32_t outDataLen);
        uint32_t Decrypt(array_view<uint8_t const> decData, uint32_t decDataLen, array_view<uint8_t> outData);
        uint32_t Decrypt(uint64_t decData, uint32_t decDataLen, uint64_t outData, uint32_t outDataLen);
        int32_t EncryptAuth(uint64_t encData, uint32_t encDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen);
        int32_t DecryptAuth(uint64_t decData, uint32_t decDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen);

        virtual ~SodiumCryptor() noexcept;
    };
}
