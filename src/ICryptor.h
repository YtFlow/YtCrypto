#pragma once
#include "pch.h"

namespace YtCrypto {
	public interface class ICryptor
	{
		size_t Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		size_t Encrypt(IntPtrAbi encData, size_t encDataLen, IntPtrAbi outData, size_t outDataLen);
		size_t Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
	};
}
