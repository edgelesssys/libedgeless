#pragma once

#include <array>
#include <exception>
#include <vector>
#include "span.h"

namespace edgeless {
namespace crypto {

struct Error : std::logic_error {
  using logic_error::logic_error;
};

/**
 * AES-GCM key for encryption, decryption and derivation of new keys.
 */
class Key {
 public:
  static constexpr size_t kSizeTag = 128 / 8;
  static constexpr size_t kSizeKey = 128 / 8;

  using Buffer = tcb::span<uint8_t>;
  using CBuffer = tcb::span<const uint8_t>;

  //! Generate new key using Intel instruction RDRAND.
  Key();
  //! Set key directly.
  Key(std::vector<uint8_t> rk);
  Key(const Key&) = delete;
  Key& operator=(const Key&) = delete;

  //! Derive new key from current using a given nonce/salt.
  Key derive(CBuffer nonce) const;

  /**
   * Decrypt with AAD.
   * 
   * @param ciphertext ciphertext buffer
   * @param iv initialization vector buffer
   * @param aad additional authenticated data buffer
   * @param tag tag buffer; serves as MAC
   * @param plaintext plaintext buffer (out)
   * May be the same as ciphertext for in-place decryption.
   * @return true Decryption succeeded; the tag was valid for the given iv/ciphertext combination.
   * @return false The tag was invalid or other error.
   */
  bool decrypt(CBuffer ciphertext, CBuffer iv, CBuffer aad, CBuffer tag, Buffer plaintext) const;

  //! Decrypt without AAD.
  bool decrypt(CBuffer ciphertext, CBuffer iv, CBuffer tag, Buffer plaintext) const;

  //! Decrypt with AAD only.
  bool decrypt(CBuffer iv, CBuffer aad, CBuffer tag) const;

  /**
   * Encrypt with AAD.
   * 
   * @param plaintext plaintext buffer
   * @param iv initialization vector buffer
   * MUST NEVER repeat for an encryption key!
   * @param aad additional authenticated data buffer
   * @param tag tag buffer (out); serves as MAC
   * @param ciphertext ciphertext buffer (out)
   * May be the same as plaintext for in-place encryption.
   */
  void encrypt(CBuffer plaintext, CBuffer iv, CBuffer aad, Buffer tag, Buffer ciphertext) const;

  //! Encrypt without AAD.
  void encrypt(CBuffer plaintext, CBuffer iv, Buffer tag, Buffer ciphertext) const;

  //! Encrypt with AAD only. This can be used to protect the integrity of plaintext.
  void encrypt(CBuffer iv, CBuffer aad, Buffer tag) const;

 protected:
  static constexpr auto kMaxRetriesRand = 8u;
  std::vector<uint8_t> rk_;
};

using Tag = std::array<uint8_t, Key::kSizeTag>;

}  // namespace crypto
}  // namespace edgeless