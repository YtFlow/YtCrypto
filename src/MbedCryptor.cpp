#include <vector>
#include "pch.h"
#include "MbedCryptor.h"

using namespace YtCrypto;
using namespace Platform;

namespace YtCrypto
{
	MbedCryptor::MbedCryptor(std::shared_ptr<uint8> key, size_t keyLen, std::unique_ptr<uint8> iv, size_t ivLen, mbedtls_cipher_type_t cipher_type)
		: key(key), iv(std::move(iv)), keyLen(keyLen), ivLen(ivLen)
	{
		mbedtls_cipher_init(&encctx);
		mbedtls_cipher_init(&decctx);
		mbedtls_cipher_setup(&encctx, mbedtls_cipher_info_from_type(cipher_type));
		mbedtls_cipher_setup(&decctx, mbedtls_cipher_info_from_type(cipher_type));

		if (encctx.cipher_info->mode == MBEDTLS_MODE_GCM || encctx.cipher_info->mode == MBEDTLS_MODE_CHACHAPOLY) {
			std::vector<uint8> sessionKey(keyLen);
			auto ret = Common::DeriveAuthSessionKeySha1(&*this->iv, ivLen, &*key, keyLen, sessionKey.data(), sessionKey.size());
			if (ret != 0) {
				throw ref new InvalidArgumentException(L"Cannot derive enc session key, Mbed TLS returned: " + ret.ToString());
			}
			mbedtls_cipher_setkey(&encctx, sessionKey.data(), 8 * (int)keyLen, MBEDTLS_ENCRYPT);
		}
		else if (cipher_type == mbedtls_cipher_type_t::MBEDTLS_CIPHER_ARC4_128) {
			std::array<uint8, MD5_LEN> realEncKey;
			if (!Common::GenerateKeyMd5(&*key, keyLen, &*(this->iv), ivLen, realEncKey.data())) {
				throw ref new FailureException(L"Cannot derive enc key using md5");
			}
			mbedtls_cipher_setkey(&encctx, realEncKey.data(), 8 * (int)keyLen, MBEDTLS_ENCRYPT);
		}
		else {
			mbedtls_cipher_setkey(&encctx, &*key, 8 * (int)keyLen, MBEDTLS_ENCRYPT);
			mbedtls_cipher_setkey(&decctx, &*key, 8 * (int)keyLen, MBEDTLS_DECRYPT);
		}
		mbedtls_cipher_set_iv(&encctx, &*(this->iv), ivLen);
	}

	size_t MbedCryptor::Encrypt(uint8* encData, size_t encDataLen, uint8* outData, size_t outDataLen)
	{
		size_t len;
		size_t realDataOffset = 0;
		if (!enc_iv_inited) {
			enc_iv_inited = true;
			if (outDataLen - encDataLen < ivLen) throw ref new InvalidArgumentException(L"Not enough space for IV");
			// outData->Length >= ivLen
			if (memcpy_s(outData, outDataLen, &*iv, ivLen)) throw ref new OutOfBoundsException("Cannot copy iv to outData");
			realDataOffset += ivLen;
		}
		mbedtls_cipher_update(&encctx, encData, encDataLen, outData + realDataOffset, &len);
		return len + realDataOffset;
	}

	size_t MbedCryptor::Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData) {
		return Encrypt(encData->Data, encDataLen, outData->Data, outData->Length);
	}

	size_t MbedCryptor::Encrypt(IntPtrAbi encData, size_t encDataLen, IntPtrAbi outData, size_t outDataLen) {
		return Encrypt((uint8*)(void*)encData, encDataLen, (uint8*)(void*)outData, outDataLen);
	}

	size_t MbedCryptor::Decrypt(uint8* decData, size_t decDataLen, uint8* outData, size_t outDataLen)
	{
		auto realDecData = decData;
		auto realLen = decDataLen;
		if (!dec_iv_inited) {
			if (decDataLen < ivLen) throw ref new InvalidArgumentException(L"IV not enough");
			dec_iv_inited = true;
			mbedtls_cipher_set_iv(&decctx, decData, ivLen);
			if (decctx.cipher_info->type == MBEDTLS_CIPHER_ARC4_128) {
				std::array<uint8, MD5_LEN> realDecKey;
				if (!Common::GenerateKeyMd5(&*key, keyLen, decData, ivLen, realDecKey.data())) {
					throw ref new FailureException(L"Cannot derive dec key using md5");
				}
				mbedtls_cipher_setkey(&decctx, realDecKey.data(), 8 * (int)keyLen, MBEDTLS_DECRYPT);
			}
			realDecData += ivLen;
			realLen -= ivLen;
			if (realLen == 0) {
				return 0;
			}
		}
		size_t len;
		mbedtls_cipher_update(&decctx, realDecData, realLen, outData, &len);
		return len;
	}

	size_t MbedCryptor::Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData)
	{
		return Decrypt(decData->Data, decData->Length, outData->Data, outData->Length);
	}

	size_t MbedCryptor::Decrypt(IntPtrAbi decData, size_t decDataLen, IntPtrAbi outData, size_t outDataLen)
	{
		return Decrypt((uint8*)(void*)decData, decDataLen, (uint8*)(void*)outData, outDataLen);
	}

	int MbedCryptor::EncryptAuth(uint8* encData, int encDataLen, uint8* tagData, size_t tagDataSize, uint8* outData, int outDataLen) {
		if (!enc_iv_inited && outDataLen - ivLen < encDataLen || outDataLen < encDataLen) {
			throw ref new InvalidArgumentException("outDataSize too small");
		}
		if (!enc_iv_inited) {
			enc_iv_inited = true;
			if (memcpy_s(outData, outDataLen, &*iv, ivLen)) throw ref new OutOfBoundsException("Cannot copy iv to outData");
			outData += ivLen;
			if (encDataLen == 0) {
				return ivLen;
			}
			encDataLen -= ivLen;
		}
		size_t size;
		auto ret = mbedtls_cipher_auth_encrypt(&encctx, encNonce.data(), encNonce.size(), nullptr, 0, encData, encDataLen, outData, &size, tagData, tagDataSize);
		if (ret != 0) {
			return ret;
		}
		Common::SodiumIncrement(encNonce.data(), encNonce.size());
		return size;
	}

	int MbedCryptor::DecryptAuth(uint8* decData, int decDataLen, uint8* tagData, size_t tagDataSize, uint8* outData, int outDataLen) {
		if (!dec_iv_inited && outDataLen < decDataLen - ivLen || dec_iv_inited && outDataLen < decDataLen) {
			throw ref new Platform::InvalidArgumentException("outDataSize too small");
		}
		if (!dec_iv_inited) {
			if (decDataLen < ivLen) throw ref new InvalidArgumentException(L"IV not enough");
			dec_iv_inited = true;
			std::vector<uint8> sessionKey(keyLen);
			auto ret = Common::DeriveAuthSessionKeySha1(decData, decDataLen, &*key, keyLen, sessionKey.data(), sessionKey.size());
			if (ret != 0) {
				throw ref new InvalidArgumentException(L"Cannot derive dec session key, Mbed TLS returned: " + ret.ToString());
			}
			mbedtls_cipher_setkey(&decctx, sessionKey.data(), 8 * (int)keyLen, MBEDTLS_DECRYPT);
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
		Common::SodiumIncrement(decNonce.data(), decNonce.size());
		return size;
	}

	int MbedCryptor::EncryptAuth(IntPtrAbi encData, int encDataLen, IntPtrAbi tagData, size_t tagDataLen, IntPtrAbi outData, int outDataLen) {
		return EncryptAuth((uint8*)(void*)encData, encDataLen, (uint8*)(void*)tagData, tagDataLen, (uint8*)(void*)outData, outDataLen);
	}

	int MbedCryptor::DecryptAuth(IntPtrAbi decData, int decDataLen, IntPtrAbi tagData, size_t tagDataLen, IntPtrAbi outData, int outDataLen) {
		return DecryptAuth((uint8*)(void*)decData, decDataLen, (uint8*)(void*)tagData, tagDataLen, (uint8*)(void*)outData, outDataLen);
	}

	uint64 MbedCryptor::IvLen::get() {
		return ivLen;
	}

	MbedCryptor::~MbedCryptor()
	{
		mbedtls_cipher_free(&encctx);
		mbedtls_cipher_free(&decctx);
	}
}
