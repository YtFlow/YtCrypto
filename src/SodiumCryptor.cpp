#include "SodiumCryptor.h"

using namespace YtCrypto;
using namespace Platform;

namespace YtCrypto
{
	SodiumCryptor::SodiumCryptor(std::shared_ptr<uint8[]> key, size_t keyLen, std::unique_ptr<uint8[]> iv, size_t ivLen, mbedtls_cipher_type_t cipher_type)
		: key(key), encIv(std::move(iv)), keyLen(keyLen), ivLen(ivLen), encKey(std::make_unique<uint8[]>(keyLen)), algorithm(static_cast<Algorithm>(cipher_type))
	{
		if (cipher_type == Algorithm::Chacha20Poly1305 || cipher_type == Algorithm::XChacha20Poly1305) {
			encKey = std::make_unique<uint8[]>(keyLen);
			auto ret = Common::DeriveAuthSessionKeySha1(encIv.get(), ivLen, key.get(), keyLen, encKey.get(), keyLen);
			if (ret != 0) {
				throw ref new InvalidArgumentException(L"Cannot derive enc session key, Mbed TLS returned: " + ret.ToString());
			}
			encBuf = std::vector<uint8>(SODIUM_BLOCK_SIZE + MAX_BLOCK_SIZE);
			decBuf = std::vector<uint8>(SODIUM_BLOCK_SIZE + MAX_BLOCK_SIZE);
		}
		else {
			decKey = key;
			encKey = key;
		}
	}

	size_t SodiumCryptor::Encrypt(uint8* encData, size_t encDataLen, uint8* outData, size_t outDataLen)
	{
		size_t realDataOffset = 0;
		if (!enc_iv_inited) {
			enc_iv_inited = true;
			if (outDataLen - encDataLen < ivLen) throw ref new InvalidArgumentException(L"Not enough space for IV");
			// outData->Length >= ivLen
			if (memcpy_s(outData, outDataLen, encIv.get(), ivLen)) throw ref new OutOfBoundsException(L"Cannot copy iv to outData");
			realDataOffset += ivLen;
		}

		int padding = encCounter % SODIUM_BLOCK_SIZE;
		encBuf.resize(padding + encDataLen);
		mbedtls_platform_zeroize(encBuf.data(), padding);
		if (memcpy_s(encBuf.data() + padding, encDataLen, encData, encDataLen)) throw ref new InvalidArgumentException(L"Cannot move data after padding");

		switch (algorithm)
		{
		case Algorithm::Salsa20:
			crypto_stream_salsa20_xor_ic(encBuf.data(), encBuf.data(), encBuf.size(), encIv.get(), encCounter / SODIUM_BLOCK_SIZE, encKey.get());
			break;
		default:
			throw ref new NotImplementedException(L"Unsupported cipher");
		}

		if (memcpy_s(outData + realDataOffset, outDataLen - realDataOffset, encBuf.data() + padding, encBuf.size() - padding)) throw ref new OutOfBoundsException("Cannot copy out data");
		encCounter += encDataLen;
		return encDataLen + realDataOffset;
	}

	size_t SodiumCryptor::Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData) {
		return Encrypt(encData->Data, encDataLen, outData->Data, outData->Length);
	}

	size_t SodiumCryptor::Encrypt(IntPtrAbi encData, size_t encDataLen, IntPtrAbi outData, size_t outDataLen) {
		return Encrypt((uint8*)(void*)encData, encDataLen, (uint8*)(void*)outData, outDataLen);
	}

	size_t SodiumCryptor::Decrypt(uint8* decData, size_t decDataLen, uint8* outData, size_t outDataLen)
	{
		auto realDecData = decData;
		auto realLen = decDataLen;
		if (!dec_iv_inited) {
			if (decDataLen < ivLen) throw ref new InvalidArgumentException(L"IV not enough");
			dec_iv_inited = true;
			decIv = std::make_unique<uint8[]>(ivLen);
			if (memcpy_s(decIv.get(), ivLen, decData, IvLen)) throw ref new InvalidArgumentException(L"Cannot get iv");
			realDecData += ivLen;
			realLen -= ivLen;
			if (realLen == 0) {
				return 0;
			}
		}

		int padding = decCounter % SODIUM_BLOCK_SIZE;
		decBuf.resize(padding + realLen);
		mbedtls_platform_zeroize(decBuf.data(), padding);
		if (memcpy_s(decBuf.data() + padding, realLen, realDecData, realLen)) throw ref new InvalidArgumentException(L"Cannot move data after padding");

		switch (algorithm)
		{
		case Algorithm::Salsa20:
			crypto_stream_salsa20_xor_ic(decBuf.data(), decBuf.data(), padding + realLen, decIv.get(), decCounter / SODIUM_BLOCK_SIZE, decKey.get());
			break;
		default:
			throw ref new InvalidArgumentException(L"Unsupported cipher");
		}

		return realLen;
	}

	size_t SodiumCryptor::Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData)
	{
		return Decrypt(decData->Data, decData->Length, outData->Data, outData->Length);
	}

	size_t SodiumCryptor::Decrypt(IntPtrAbi decData, size_t decDataLen, IntPtrAbi outData, size_t outDataLen)
	{
		return Decrypt((uint8*)(void*)decData, decDataLen, (uint8*)(void*)outData, outDataLen);
	}

	int SodiumCryptor::EncryptAuth(uint8* encData, int encDataLen, uint8* tagData, size_t tagDataSize, uint8* outData, int outDataLen) {
		if (!enc_iv_inited && outDataLen - ivLen < encDataLen || outDataLen < encDataLen) {
			throw ref new InvalidArgumentException("outDataSize too small");
		}
		uint8* realOutData = outData;
		if (!enc_iv_inited) {
			enc_iv_inited = true;
			if (memcpy_s(outData, outDataLen, encIv.get(), ivLen)) throw ref new OutOfBoundsException("Cannot copy iv to outData");
			realOutData += ivLen;
			if (encDataLen == 0) {
				return ivLen;
			}
			outDataLen -= ivLen;
		}
		uint64 tagSize, size;
		int ret;
		switch (algorithm)
		{
		case YtCrypto::XChacha20Poly1305:
			ret = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(realOutData, tagData, &tagSize, encData, encDataLen, NULL, 0, NULL, encNonce.data(), encKey.get());
			break;
		default:
			throw ref new NotImplementedException("Unsupported cipher");
		}
		if (tagSize != 16) throw ref new NotImplementedException(L"Unexpected tag size: " + tagSize);
		if (ret != 0) {
			return ret;
		}
		Common::SodiumIncrement(encNonce.data(), encNonce.size());
		return realOutData - outData + encDataLen;
	}

	int SodiumCryptor::DecryptAuth(uint8* decData, int decDataLen, uint8* tagData, size_t tagDataSize, uint8* outData, int outDataLen) {
		if (!dec_iv_inited && outDataLen < decDataLen - ivLen || dec_iv_inited && outDataLen < decDataLen) {
			throw ref new Platform::InvalidArgumentException("outDataSize too small");
		}
		if (!dec_iv_inited) {
			if (decDataLen < ivLen) throw ref new InvalidArgumentException(L"IV not enough");
			dec_iv_inited = true;
			decKey = std::shared_ptr<uint8[]>(new uint8[keyLen]);
			auto ret = Common::DeriveAuthSessionKeySha1(decData, ivLen, key.get(), keyLen, decKey.get(), keyLen);
			if (ret != 0) {
				throw ref new InvalidArgumentException(L"Cannot derive dec session key, Mbed TLS returned: " + ret.ToString());
			}
			decIv = std::make_unique<uint8[]>(ivLen);
			if (!memcpy_s(decIv.get(), ivLen, decData, ivLen)) throw ref new InvalidArgumentException(L"Cannot get iv");
			decData += ivLen;
			decDataLen -= ivLen;
			if (decDataLen == 0) {
				return 0;
			}
		}
		int ret;
		switch (algorithm) {
		case Algorithm::XChacha20Poly1305:
			ret = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(outData, NULL, decData, decDataLen, tagData, NULL, 0, decNonce.data(), decKey.get());
			break;
		default:
			throw ref new NotImplementedException("Unsupported cipher");
		}
		if (ret != 0) {
			return ret;
		}
		Common::SodiumIncrement(decNonce.data(), decNonce.size());
		return decDataLen;
	}

	int SodiumCryptor::EncryptAuth(IntPtrAbi encData, int encDataLen, IntPtrAbi tagData, size_t tagDataLen, IntPtrAbi outData, int outDataLen) {
		return EncryptAuth((uint8*)(void*)encData, encDataLen, (uint8*)(void*)tagData, tagDataLen, (uint8*)(void*)outData, outDataLen);
	}

	int SodiumCryptor::DecryptAuth(IntPtrAbi decData, int decDataLen, IntPtrAbi tagData, size_t tagDataLen, IntPtrAbi outData, int outDataLen) {
		return DecryptAuth((uint8*)(void*)decData, decDataLen, (uint8*)(void*)tagData, tagDataLen, (uint8*)(void*)outData, outDataLen);
	}

	uint64 SodiumCryptor::IvLen::get() {
		return ivLen;
	}

	SodiumCryptor::~SodiumCryptor()
	{
		mbedtls_platform_zeroize(encIv.get(), ivLen);
		mbedtls_platform_zeroize(decIv.get(), ivLen);
		if (algorithm == Algorithm::Chacha20Poly1305 || algorithm == Algorithm::XChacha20Poly1305) {
			mbedtls_platform_zeroize(encNonce.data(), encNonce.size());
			mbedtls_platform_zeroize(decNonce.data(), decNonce.size());
		}
		else {
			mbedtls_platform_zeroize(encBuf.data(), encBuf.size());
			mbedtls_platform_zeroize(decBuf.data(), decBuf.size());
		}
	}
}
