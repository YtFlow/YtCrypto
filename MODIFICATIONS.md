# Modifications to 3rd-party libraries

## Mbed TLS
- `include/mbedtls/config.h`
  - Uncommented `#define MBEDTLS_NO_PLATFORM_ENTROPY` because WinRT does not support `Crypt*` functions
- `library/x509_crt.c`
  - Replaced `lstrlenW` by `StringCbLengthW` because WinRT does not support `lstrlenW`
