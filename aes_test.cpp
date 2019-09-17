#include "block.h"
#include "crypto.h"

#include "aes.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <chrono>
#include <vector>

const size_t NUM_IT = 100000000;

using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::high_resolution_clock;

gc::FastRNG rng;
auto key = rng.fill_random_16();
std::vector<gc::Block> buf(4);
std::vector<gc::Block> output(4);

void test_openssl() {
  auto ctx = EVP_CIPHER_CTX_new();
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, gc::byte_array(key),
                         NULL) != 1) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  int32_t outl;
  auto t1 = high_resolution_clock::now();
  for (size_t it = 0; it < NUM_IT; ++it) {
    for (size_t i = 0; i < 4; ++i) {
      if (EVP_EncryptUpdate(ctx, gc::byte_array(output[i]), &outl,
                            gc::byte_array(buf[i]), 16) != 1) {
        ERR_print_errors_fp(stderr);
        exit(1);
      }
    }
  }
  auto t2 = high_resolution_clock::now();
  std::cout << "Time: " << duration_cast<duration<double>>(t2 - t1).count()
            << std::endl;
  for (size_t i = 0; i < 4; ++i) {
    gc::print_block(output[i]);
  }
  std::cout << "---" << std::endl;
}

void test_openssl_batch() {
  auto ctx = EVP_CIPHER_CTX_new();
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, gc::byte_array(key),
                         NULL) != 1) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  int32_t outl;
  auto t1 = high_resolution_clock::now();
  for (size_t it = 0; it < NUM_IT; ++it) {
    if (EVP_EncryptUpdate(ctx, gc::byte_array(output[0]), &outl,
                          gc::byte_array(buf[0]), 64) != 1) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
  }
  auto t2 = high_resolution_clock::now();
  std::cout << "Time: " << duration_cast<duration<double>>(t2 - t1).count()
            << std::endl;
  for (size_t i = 0; i < 4; ++i) {
    gc::print_block(output[i]);
  }
  std::cout << "---" << std::endl;
}

void test_tinygarble() {
  AES_KEY aes_key;
  AESSetEncryptKey(gc::byte_array(key), 128, &aes_key);
  auto t1 = high_resolution_clock::now();
  for (size_t it = 0; it < NUM_IT; ++it) {
    output = buf;
    AESEcbEncryptBlks(output.data(), 4, &aes_key);
  }
  auto t2 = high_resolution_clock::now();
  std::cout << "Time: " << duration_cast<duration<double>>(t2 - t1).count()
            << std::endl;
  for (size_t i = 0; i < 4; ++i) {
    gc::print_block(output[i]);
  }
  std::cout << "---" << std::endl;
}

int main() {
  for (size_t i = 0; i < 4; ++i) {
    buf[i] = rng.fill_random_16();
    gc::print_block(buf[i]);
  }
  std::cout << "---" << std::endl;
  test_openssl();
  test_openssl_batch();
  test_tinygarble();
  return 0;
}
