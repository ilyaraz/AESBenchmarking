#pragma once

#include <emmintrin.h>

#include <cstdint>
#include <iostream>

namespace gc {
using Block = __m128i;

const Block zero_block =
    _mm_setr_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

inline Block band(const Block &a, const Block &b) {
  return _mm_and_si128(a, b);
}

inline Block bxor(const Block &a, const Block &b) {
  return _mm_xor_si128(a, b);
}

inline uint8_t *byte_array(Block &a) { return reinterpret_cast<uint8_t *>(&a); }

inline const uint8_t *byte_array(const Block &a) {
  return reinterpret_cast<const uint8_t *>(&a);
}

inline void print_block(const Block &a) {
  auto bytes = byte_array(a);
  for (int32_t i = 0; i < 16; ++i) {
    std::cout << static_cast<int32_t>(bytes[i]) << " ";
  }
  std::cout << std::endl;
}
}  // namespace gc
