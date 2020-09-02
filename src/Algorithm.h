#pragma once
#include "mbedtls\cipher.h"

namespace YtCrypto {
    enum Algorithm {
        Chacha20 = MBEDTLS_CIPHER_CHACHA20,
        Salsa20 = MBEDTLS_CIPHER_ARC4_128,
        Chacha20Poly1305 = MBEDTLS_CIPHER_CHACHA20_POLY1305,
        XChacha20Poly1305 = MBEDTLS_CIPHER_AES_128_CCM
    };
}
