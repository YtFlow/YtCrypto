#include "CipherInfo.h"

namespace YtCrypto {
    std::unordered_map<winrt::hstring, factory_creator_t*> CipherInfo::Ciphers = {
        /* Stream ciphers */
        {L"rc4-md5", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_ARC4_128, 16, 16>},
        {L"rc4-md5", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_ARC4_128, 16, 16>},
        {L"aes-128-cfb", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_128_CFB128, 16, 16>},
        {L"aes-192-cfb", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_192_CFB128, 24, 16>},
        {L"aes-256-cfb", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_256_CFB128, 32, 16>},
        {L"aes-128-ctr", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_128_CTR, 16, 16>},
        {L"aes-192-ctr", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_192_CTR, 24, 16>},
        {L"aes-256-ctr", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_AES_256_CTR, 32, 16>},
        {L"camellia-128-cfb", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_CAMELLIA_128_CFB128, 16, 16>},
        {L"camellia-192-cfb", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_CAMELLIA_192_CFB128, 24, 16>},
        {L"camellia-256-cfb", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_CAMELLIA_256_CFB128, 32, 16>},
        {L"salsa20", &CipherInfo::FactoryCreator<CryptorProvider::SodiumStream, (mbedtls_cipher_type_t)Algorithm::Salsa20, crypto_stream_salsa20_KEYBYTES, crypto_stream_salsa20_NONCEBYTES>},
        {L"chacha20", &CipherInfo::FactoryCreator<CryptorProvider::SodiumStream, (mbedtls_cipher_type_t)Algorithm::Chacha20, crypto_stream_chacha20_KEYBYTES, crypto_stream_chacha20_NONCEBYTES>},
        {L"chacha20-ietf", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsStream, MBEDTLS_CIPHER_CHACHA20, 32, 12>},

        /* AEAD ciphers */
        {L"aes-128-gcm", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsAuth, MBEDTLS_CIPHER_AES_128_GCM, 16, 16, 12, 16>},
        {L"aes-192-gcm", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsAuth, MBEDTLS_CIPHER_AES_192_GCM, 24, 24, 12, 16>},
        {L"aes-256-gcm", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsAuth, MBEDTLS_CIPHER_AES_256_GCM, 32, 32, 12, 16>},
        {L"chacha20-ietf-poly1305", &CipherInfo::FactoryCreator<CryptorProvider::MbedtlsAuth, MBEDTLS_CIPHER_CHACHA20_POLY1305, 32, 32, 12, 16>},
        {L"chacha20-poly1305", &CipherInfo::FactoryCreator<CryptorProvider::SodiumAuth, (mbedtls_cipher_type_t)Algorithm::Chacha20Poly1305, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_NPUBBYTES, 16>},
        {L"xchacha20-ietf-poly1305", &CipherInfo::FactoryCreator<CryptorProvider::SodiumAuth, (mbedtls_cipher_type_t)Algorithm::XChacha20Poly1305, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 16>},
    };
}
