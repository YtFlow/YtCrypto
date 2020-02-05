#pragma once
#include "pch.h"

namespace YtCrypto {
	public interface class ICryptor
	{
		property uint64 IvLen { uint64 get(); }
		size_t Encrypt(const Platform::Array<uint8, 1u>^ encData, size_t encDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		size_t Encrypt(IntPtrAbi encData, size_t encDataLen, IntPtrAbi outData, size_t outDataLen);
		size_t Decrypt(const Platform::Array<uint8, 1u>^ decData, size_t decDataLen, Platform::WriteOnlyArray<uint8, 1u>^ outData);
		size_t Decrypt(IntPtrAbi decData, size_t decDataLen, IntPtrAbi outData, size_t outDataLen);
		int EncryptAuth(IntPtrAbi encData, int encDataLen, IntPtrAbi tagData, size_t tagDataLen, IntPtrAbi outData, int outDataLen);
		int DecryptAuth(IntPtrAbi decData, int decDataLen, IntPtrAbi tagData, size_t tagDataLen, IntPtrAbi outData, int outDataLen);
	};
}
