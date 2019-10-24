#pragma once
#include <array>
#include <vector>
#include <exception>
#include "buffer.h"

namespace crypto {

struct Error : public std::logic_error {
  using logic_error::logic_error;
};

class Key {
public:
  static constexpr size_t kSizeTag = 128 / 8;
  static constexpr size_t kSizeKey = 128 / 8;

  // generate new key using Intel instruction RDRAND
  Key();
  Key(const Key&) = delete;

  // derive new key from current
  Key derive(CBuffer nonce) const;

  // decrypt with AAD
  bool decrypt(CBuffer ct, CBuffer iv, CBuffer aad, CBuffer tag, Buffer pt) const;

  // decrypt without AAD
  bool decrypt(CBuffer ct, CBuffer iv, CBuffer tag, Buffer pt) const;

  // decrypt with AAD only
  bool decrypt(CBuffer iv, CBuffer aad, CBuffer tag) const;

  // encrypt with AAD
  bool encrypt(CBuffer pt, CBuffer iv, CBuffer aad, Buffer tag, Buffer ct) const;

  // encrypt without AAD
  bool encrypt(CBuffer pt, CBuffer iv, Buffer tag, Buffer ct) const;

  // encrypt with AAD only
  bool encrypt(CBuffer iv, CBuffer aad, Buffer tag) const;

protected:
  Key(std::vector<uint8_t> rk) : rk_(std::move(rk)) {}

  static constexpr auto kMaxRetriesRand = 8u;
  std::vector<uint8_t> rk_;
};

using Tag = std::array<uint8_t, Key::kSizeTag>;

}  // namespace crypto