#include "winrt\YtCrypto.h"
#include "CryptorFactory.h"

void* winrt_make_YtCrypto_CryptorFactory()
{
    return winrt::detach_abi(winrt::make<winrt::YtCrypto::factory_implementation::CryptorFactory>());
}
