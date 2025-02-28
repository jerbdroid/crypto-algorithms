#pragma once

/*************************** HEADER FILES ***************************/
#include <array>
#include <cstdint>
#include <span>

namespace crypto {

/****************************** CONSTEXPR ******************************/
constexpr size_t SHA256BlockSize{32};  // SHA256 outputs a 32 byte digestp

/**************************** DATA TYPES ****************************/
using Byte = uint8_t;   // 8-bit byte
using Word = uint32_t;  // 32-bit word, change to "long" for 16-bit machines

struct SHA256_CTX {
  std::array<Byte, 64> data;
  Word datalen;
  unsigned long long bitlen;
  std::array<Word, 8> state;
};

/*********************** FUNCTION DECLARATIONS **********************/

void sha256Init(SHA256_CTX& ctx);
void sha256Update(SHA256_CTX& ctx, std::span<const Byte> data);  // const BYTE data[], size_t len);
void sha256Final(SHA256_CTX& ctx, std::span<Byte> hash);

}  // namespace crypto
