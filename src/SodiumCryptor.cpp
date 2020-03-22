#include "pch.h"
#include "SodiumCryptor.h"
#include "SodiumCryptor.g.cpp"

namespace winrt::YtCrypto::implementation
{
    int SodiumCryptor::Encrypt(const uint8_t* encData, int encDataLen, uint8_t* outData, int outDataLen)
    {
        int realDataOffset = 0;
        if (!enc_iv_inited) {
            enc_iv_inited = true;
            if (outDataLen - encDataLen < ivLen) {
                throw hresult_invalid_argument(L"Not enough space for IV");
            }
            // outData->Length >= ivLen
            if (memcpy_s(outData, outDataLen, encIv.get(), ivLen)) {
                throw hresult_out_of_bounds(L"Cannot copy iv to outData");
            }
            realDataOffset += ivLen;
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

        switch (algorithm)
        {
        case Algorithm::Salsa20:
            crypto_stream_salsa20_xor_ic(outputBuf, inputBuf, inputSize, encIv.get(), encCounter / SODIUM_BLOCK_SIZE, key.get());
            break;
        case Algorithm::Chacha20:
            crypto_stream_chacha20_xor_ic(outputBuf, inputBuf, inputSize, encIv.get(), encCounter / SODIUM_BLOCK_SIZE, key.get());
            break;
        default:
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
    int SodiumCryptor::Decrypt(const uint8_t* decData, int decDataLen, uint8_t* outData, int outDataLen)
    {
		auto realDecData = decData;
        auto realLen = decDataLen;
        if (!dec_iv_inited) {
            if (decDataLen < ivLen) {
                throw hresult_invalid_argument(L"IV not enough");
            }
            dec_iv_inited = true;
            decIv = std::make_unique<uint8_t[]>(ivLen);
            if (memcpy_s(decIv.get(), ivLen, decData, ivLen)) {
                throw hresult_out_of_bounds(L"Cannot get iv");
            }
            realDecData += ivLen;
            realLen -= ivLen;
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

        switch (algorithm)
        {
        case Algorithm::Salsa20:
            crypto_stream_salsa20_xor_ic(outputBuf, inputBuf, inputSize, decIv.get(), decCounter / SODIUM_BLOCK_SIZE, key.get());
            break;
        case Algorithm::Chacha20:
		    crypto_stream_chacha20_xor_ic(outputBuf, inputBuf, inputSize, decIv.get(), decCounter / SODIUM_BLOCK_SIZE, key.get());
		    break;
        default:
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
    int SodiumCryptor::EncryptAuth(const uint8_t* encData, int encDataLen, uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen)
    {
        if (!enc_iv_inited && outDataLen - ivLen < encDataLen || outDataLen < encDataLen) {
            throw hresult_invalid_argument(L"outDataSize too small");
        }
        uint8_t* realOutData = outData;
        if (!enc_iv_inited) {
            enc_iv_inited = true;
            if (memcpy_s(outData, outDataLen, encIv.get(), ivLen)) {
                throw hresult_out_of_bounds(L"Cannot copy iv to outData");
            }
            realOutData += ivLen;
            if (encDataLen == 0) {
                return ivLen;
            }
            outDataLen -= ivLen;
        }
        uint64_t tagSize;
        int ret;
        switch (algorithm)
        {
        case Algorithm::Chacha20Poly1305:
            ret = crypto_aead_chacha20poly1305_encrypt_detached(realOutData, tagData, &tagSize, encData, encDataLen, NULL, 0, NULL, encNonce.get(), encKey.get());
            break;
        case Algorithm::XChacha20Poly1305:
            ret = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(realOutData, tagData, &tagSize, encData, encDataLen, NULL, 0, NULL, encNonce.get(), encKey.get());
            break;
        default:
            throw hresult_not_implemented(L"Unsupported cipher");
        }
        if (tagSize != 16) {
            throw hresult_invalid_argument(L"Unexpected tag size: " + std::to_wstring(tagSize));
        }
        if (ret != 0) {
            return ret;
        }
        sodium_increment(encNonce.get(), nonceLen);
        return (int)(realOutData - outData) + encDataLen;
    }
    int SodiumCryptor::DecryptAuth(const uint8_t* decData, int decDataLen, const uint8_t* tagData, int tagDataSize, uint8_t* outData, int outDataLen)
    {
        if (!dec_iv_inited && outDataLen < decDataLen - ivLen || dec_iv_inited && outDataLen < decDataLen) {
            throw hresult_invalid_argument(L"outDataSize too small");
        }
        if (!dec_iv_inited) {
            if (decDataLen < ivLen) {
                throw hresult_invalid_argument(L"IV not enough");
            }
            dec_iv_inited = true;
            decKey = std::shared_ptr<uint8_t[]>(new uint8_t[keyLen]);
            auto ret = Common::DeriveAuthSessionKeySha1(decData, ivLen, key.get(), keyLen, decKey.get(), keyLen);
            if (ret != 0) {
                throw hresult_invalid_argument(L"Cannot derive dec session key, Mbed TLS returned: " + std::to_wstring(ret));
            }
            decIv = std::make_unique<uint8_t[]>(ivLen);
            if (memcpy_s(decIv.get(), ivLen, decData, ivLen)) {
                throw hresult_out_of_bounds(L"Cannot get iv");
            }
            decData += ivLen;
            decDataLen -= ivLen;
            if (decDataLen == 0) {
                return 0;
            }
        }
        int ret;
        switch (algorithm) {
        case Algorithm::Chacha20Poly1305:
            ret = crypto_aead_chacha20poly1305_decrypt_detached(outData, NULL, decData, decDataLen, tagData, NULL, 0, decNonce.get(), decKey.get());
            break;
        case Algorithm::XChacha20Poly1305:
            ret = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(outData, NULL, decData, decDataLen, tagData, NULL, 0, decNonce.get(), decKey.get());
            break;
        default:
            throw hresult_not_implemented(L"Unsupported cipher");
        }
        if (ret != 0) {
            return ret;
        }
        sodium_increment(decNonce.get(), nonceLen);
        return decDataLen;
    }
    SodiumCryptor::SodiumCryptor(std::shared_ptr<uint8_t[]> key, size_t keyLen, std::unique_ptr<uint8_t[]> iv, int ivLen, mbedtls_cipher_type_t cipher_type)
		: key(key), encIv(std::move(iv)), keyLen(keyLen), ivLen(ivLen),
		encKey(std::make_unique<uint8_t[]>(keyLen)),
		algorithm(static_cast<Algorithm>(cipher_type))
    {
    }
    SodiumCryptor::SodiumCryptor(std::shared_ptr<uint8_t[]> key, size_t keyLen, std::unique_ptr<uint8_t[]> iv, int ivLen, size_t nonceLen, mbedtls_cipher_type_t cipher_type)
		: key(key), encIv(std::move(iv)), keyLen(keyLen), ivLen(ivLen),
		encKey(std::make_unique<uint8_t[]>(keyLen)), nonceLen(nonceLen),
		encNonce(std::make_unique<uint8_t[]>(nonceLen)),
		decNonce(std::make_unique<uint8_t[]>(nonceLen)),
		algorithm(static_cast<Algorithm>(cipher_type))
    {
        auto ret = Common::DeriveAuthSessionKeySha1(encIv.get(), ivLen, key.get(), keyLen, encKey.get(), keyLen);
        if (ret != 0) {
            throw hresult_invalid_argument(L"Cannot derive enc session key, Mbed TLS returned: " + std::to_wstring(ret));
        }
    }
    uint64_t SodiumCryptor::IvLen()
    {
        return ivLen;
    }
    uint32_t SodiumCryptor::Encrypt(array_view<uint8_t const> encData, uint32_t encDataLen, array_view<uint8_t> outData)
    {
        return Encrypt(encData.data(), (uint32_t)encData.size(), outData.data(), (uint32_t)outData.size());
    }
    uint32_t SodiumCryptor::Encrypt(uint64_t encData, uint32_t encDataLen, uint64_t outData, uint32_t outDataLen)
    {
        return Encrypt((const uint8_t*)encData, (uint32_t)encDataLen, (uint8_t*)outData, (uint32_t)outDataLen);
    }
    uint32_t SodiumCryptor::Decrypt(array_view<uint8_t const> decData, uint32_t decDataLen, array_view<uint8_t> outData)
    {
        return Decrypt(decData.data(), (uint32_t)decData.size(), outData.data(), (uint32_t)outData.size());
    }
    uint32_t SodiumCryptor::Decrypt(uint64_t decData, uint32_t decDataLen, uint64_t outData, uint32_t outDataLen)
    {
        return Decrypt((const uint8_t*)decData, (uint32_t)decDataLen, (uint8_t*)outData, outDataLen);
    }
    int32_t SodiumCryptor::EncryptAuth(uint64_t encData, uint32_t encDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen)
    {
        return EncryptAuth((const uint8_t*)encData, (uint32_t)encDataLen, (uint8_t*)tagData, (uint32_t)tagDataLen, (uint8_t*)outData, outDataLen);
    }
    int32_t SodiumCryptor::DecryptAuth(uint64_t decData, uint32_t decDataLen, uint64_t tagData, uint32_t tagDataLen, uint64_t outData, uint32_t outDataLen)
    {
        return DecryptAuth((const uint8_t*)decData, (uint32_t)decDataLen, (const uint8_t*)tagData, (uint32_t)tagDataLen, (uint8_t*)outData, outDataLen);
    }
    SodiumCryptor::~SodiumCryptor() noexcept
    {
		mbedtls_platform_zeroize(encIv.get(), ivLen);
		if (decIv != nullptr) {
			mbedtls_platform_zeroize(decIv.get(), ivLen);
		}
		if (nonceLen == 0) {
            if (encBuf.size() > 0) {
                mbedtls_platform_zeroize(encBuf.data(), encBuf.size());
            }
            if (decBuf.size() > 0) {
                mbedtls_platform_zeroize(decBuf.data(), decBuf.size());
            }
		}
		else {
            if (encNonce != nullptr) {
                mbedtls_platform_zeroize(encNonce.get(), nonceLen);
            }
            if (decNonce != nullptr) {
                mbedtls_platform_zeroize(decNonce.get(), nonceLen);
            }
		}
    }
}
