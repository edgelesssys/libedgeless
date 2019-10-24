#pragma once
#include <array>
#include <vector>
#include <exception>

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

  // derive new key from current
  Key derive(const uint8_t* nonce, const size_t size_nonce) const;

  // decrypt with AAD
  bool decrypt(const uint8_t* ct, const size_t size_ct, const uint8_t* iv,
               const size_t size_iv, const uint8_t* aad, size_t size_aad,
               const uint8_t* tag, uint8_t* pt) const;

  // decrypt without AAD
  bool decrypt(const uint8_t* ct, const size_t size_ct, const uint8_t* iv,
               const size_t size_iv, const uint8_t* tag, uint8_t* pt) const;

  // decrypt with AAD only
  bool decrypt(const uint8_t* iv, const size_t size_iv, const uint8_t* aad,
               size_t size_aad, const uint8_t* tag) const;

  // encrypt with AAD
  bool encrypt(const uint8_t* pt, const size_t size_pt, const uint8_t* iv,
               const size_t size_iv, const uint8_t* aad, const size_t size_aad,
               uint8_t* tag, uint8_t* ct) const;

  // encrypt without AAD
  bool encrypt(const uint8_t* pt, const size_t size_pt, const uint8_t* iv,
               const size_t size_iv, uint8_t* tag, uint8_t* ct) const;

  // encrypt with AAD only
  bool encrypt(const uint8_t* iv, const size_t size_iv, const uint8_t* aad,
               const size_t size_aad, uint8_t* tag) const;
  

private:
  Key(std::vector<uint8_t> rk);

  static constexpr auto kMaxRetriesRand = 8u;
  std::vector<uint8_t> rk_;
};

using Tag = std::array<uint8_t, Key::kSizeTag>;

}  // namespace crypto