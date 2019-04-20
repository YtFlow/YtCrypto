# Modifications to 3rd-party libraries

## Mbed TLS
- Changed `volatile unsigned char *p = v;` to `volatile unsigned char *p = (volatile unsigned char*)v;` in function `mbedtls_zeroize` in order to compile

