#pragma once

#include <winrt/base.h>
#include <Windows.h>

#ifdef _WIN64
typedef int64_t IntPtrAbi;
#else
typedef int32_t IntPtrAbi;
#endif
