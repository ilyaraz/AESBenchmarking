#pragma once

#include "block.h"

#include "aes.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <cstdint>
#include <iostream>
#include <vector>

namespace gc {

class RNG {
 public:
  RNG() {
    urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
      std::cerr << "Can't open urandom" << std::endl;
      exit(1);
    }
  }

  ~RNG() {
    if (fclose(urandom)) {
      std::cerr << "Can't fclose() urandom" << std::endl;
      exit(1);
    }
  }

  void fill_random(void *buf, size_t len) {
    if (fread(buf, 1, len, urandom) != len) {
      std::cerr << "Can't read enough (pseudo-)random bytes" << std::endl;
      exit(1);
    }
  }

 private:
  FILE *urandom;
};

// TODO: Can be much faster!!!
class FastRNG {
 public:
  FastRNG() : zeros(_mm_set_epi64x(0, 0)) {
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    RNG rng;
    rng.fill_random(byte_array(key), 16);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, byte_array(key),
                           NULL) != 1) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
  }

  ~FastRNG() { EVP_CIPHER_CTX_free(ctx); }

  Block fill_random_16() {
    int32_t outl;
    Block res;
    if (EVP_EncryptUpdate(ctx, byte_array(res), &outl, byte_array(zeros), 16) !=
        1) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    return res;
  }

 private:
  EVP_CIPHER_CTX *ctx;
  Block key;
  Block zeros;
};

Block mask = _mm_setr_epi8(1, 8, 0, 0, 8, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0);

Block gf_double(const Block &x) {
  auto bytes = byte_array(x);
  auto top_bit = bytes[15] >> 7;
  auto v1 = _mm_slli_epi64(x, 1);
  auto v2 = _mm_slli_si128(x, 8);
  v2 = _mm_srli_epi64(v2, 63);
  v1 = _mm_or_si128(v1, v2);
  if (top_bit) {
    v1 = bxor(v1, mask);
  }
  return v1;
}

// TODO: fix a bug when num > 4.
class AESHasher {
 public:
  AESHasher(const Block &key) : buf(4) {
    AESSetEncryptKey(byte_array(key), 128, &aes_key);
  }

  void hash(std::vector<Block> &input, const std::vector<Block> &id,
            int32_t num) {
    for (int32_t i = 0; i < num; ++i) {
      buf[i] = gf_double(input[i]);
      buf[i] = bxor(buf[i], id[i]);
      input[i] = buf[i];
    }
    AESEcbEncryptBlks(input.data(), num, &aes_key);
    for (int32_t i = 0; i < num; ++i) {
      input[i] = bxor(input[i], buf[i]);
    }
  }

 private:
  AES_KEY aes_key;
  std::vector<Block> buf;
};

// TODO: can be much faster!
class PRG {
 public:
  PRG(Block &key) {
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, byte_array(key),
                           NULL) != 1) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
  }

  inline void run(Block &seed, Block &seed1, Block &seed2) {
    int32_t outl;
    if (EVP_EncryptUpdate(ctx, byte_array(seed1), &outl, byte_array(seed),
                          16) != 1) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    byte_array(seed)[0] ^= 1;
    if (EVP_EncryptUpdate(ctx, byte_array(seed2), &outl, byte_array(seed),
                          16) != 1) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    byte_array(seed)[0] ^= 1;
  }

  ~PRG() { EVP_CIPHER_CTX_free(ctx); }

 private:
  EVP_CIPHER_CTX *ctx;
};

}  // namespace gc
