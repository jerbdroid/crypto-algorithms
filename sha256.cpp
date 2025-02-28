
#include "sha256.hpp"

#include <memory.h>
#include <span>

namespace crypto {

constexpr auto RotateRight(Word a, Word b) -> Word {
  return (a >> b) | (a << (32 - b));
}

constexpr auto Choose(Word x, Word y, Word z) -> Word {
  return (x & y) ^ (~x & z);
}

constexpr auto Majority(Word x, Word y, Word z) -> Word {
  return (x & y) ^ (x & z) ^ (y & z);
}

constexpr auto UpperSigma0(Word x) -> Word {
  return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22);
}

constexpr auto UpperSigma1(Word x) -> Word {
  return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25);
}

constexpr auto LowerSigma0(Word x) -> Word {
  return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
}

constexpr auto LowerSigma1(Word x) -> Word {
  return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
}

static std::array<const Word, 64> k = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256_transform(SHA256_CTX* ctx, std::span<const Byte> data) {
  Word i;
  Word j;
  Word t1;
  Word t2;
  std::array<Word, 64> m;
  for (i = 0, j = 0; i < 16; ++i, j += 4) {
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
  }

  for (; i < 64; ++i) {
    m[i] = LowerSigma1(m[i - 2]) + m[i - 7] + LowerSigma0(m[i - 15]) + m[i - 16];
  }

  Word a = ctx->state[0];
  Word b = ctx->state[1];
  Word c = ctx->state[2];
  Word d = ctx->state[3];
  Word e = ctx->state[4];
  Word f = ctx->state[5];
  Word g = ctx->state[6];
  Word h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    t1 = h + UpperSigma1(e) + Choose(e, f, g) + k[i] + m[i];
    t2 = UpperSigma0(a) + Majority(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sha256Init(SHA256_CTX& ctx) {
  ctx.datalen = 0;
  ctx.bitlen = 0;
  ctx.state[0] = 0x6a09e667;
  ctx.state[1] = 0xbb67ae85;
  ctx.state[2] = 0x3c6ef372;
  ctx.state[3] = 0xa54ff53a;
  ctx.state[4] = 0x510e527f;
  ctx.state[5] = 0x9b05688c;
  ctx.state[6] = 0x1f83d9ab;
  ctx.state[7] = 0x5be0cd19;
}

void sha256Update(SHA256_CTX& ctx, const std::span<Byte> data) {
  for (const auto& data_chunk : data) {
    ctx.data[ctx.datalen] = data_chunk;
    ctx.datalen++;
    if (ctx.datalen == 64) {
      sha256_transform(&ctx, ctx.data);
      ctx.bitlen += 512;
      ctx.datalen = 0;
    }
  }
}

void sha256Final(SHA256_CTX& ctx, std::span<Byte> hash) {
  Word i;

  i = ctx.datalen;

  // Pad whatever data is left in the buffer.
  if (ctx.datalen < 56) {
    ctx.data[i++] = 0x80;
    while (i < 56) {
      ctx.data[i++] = 0x00;
    }
  } else {
    ctx.data[i++] = 0x80;
    while (i < 64) {
      ctx.data[i++] = 0x00;
    }
    sha256_transform(&ctx, ctx.data);
    memset(ctx.data.data(), 0, 56);
  }

  // Append to the padding the total message's length in bits and transform.
  ctx.bitlen += ctx.datalen * 8;
  ctx.data[63] = ctx.bitlen;
  ctx.data[62] = ctx.bitlen >> 8;
  ctx.data[61] = ctx.bitlen >> 16;
  ctx.data[60] = ctx.bitlen >> 24;
  ctx.data[59] = ctx.bitlen >> 32;
  ctx.data[58] = ctx.bitlen >> 40;
  ctx.data[57] = ctx.bitlen >> 48;
  ctx.data[56] = ctx.bitlen >> 56;
  sha256_transform(&ctx, ctx.data);

  // Since this implementation uses little endian byte ordering and SHA uses big endian,
  // reverse all the bytes when copying the final state to the output hash.
  for (i = 0; i < 4; ++i) {
    hash[i] = (ctx.state[0] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 4] = (ctx.state[1] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 8] = (ctx.state[2] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 12] = (ctx.state[3] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 16] = (ctx.state[4] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 20] = (ctx.state[5] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 24] = (ctx.state[6] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 28] = (ctx.state[7] >> (24 - i * 8)) & 0x000000ff;
  }
}

}  // namespace crypto