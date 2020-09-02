#pragma once

template <int NonceSize, int TagSize>
struct AeadMixin {
    std::array<uint8_t, NonceSize> encNonce = { 0 };
    std::array<uint8_t, NonceSize> decNonce = { 0 };
};

template <int NonceSize>
struct AeadMixin<NonceSize, 0> {};

template <int TagSize>
struct AeadMixin<0, TagSize> {};

template <>
struct AeadMixin<0, 0> {};

