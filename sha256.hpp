#pragma once

/*************************** HEADER FILES ***************************/
#include <span>

namespace crypto {

/****************************** CONSTEXPR ******************************/
constexpr size_t SHA256BlockSize{32};  // SHA256 outputs a 32 byte digestp

/**************************** DATA TYPES ****************************/
using BYTE = unsigned char;  // 8-bit byte
using WORD = unsigned int;   // 32-bit word, change to "long" for 16-bit machines

struct SHA256_CTX {
  BYTE data[64];
  WORD datalen;
  unsigned long long bitlen;
  WORD state[8];
};

/*********************** FUNCTION DECLARATIONS **********************/

void sha256Init(SHA256_CTX& ctx);
void sha256Update(SHA256_CTX& ctx, const std::span<BYTE> data);  // const BYTE data[], size_t len);
void sha256Final(SHA256_CTX& ctx, std::span<BYTE> hash);

}  // namespace crypto
