#pragma once

#include <array>
#include <atomic>
#include <exception>
#include <vector>

#include "buffer.h"

#ifndef NDEBUG
#include <mutex>
#include <set>
#endif

namespace edgeless {
namespace crypto {

struct Error : std::logic_error {
  using logic_error::logic_error;
};

/**
 * Secure random number generator using RDRAND for seeding.
 */
class RNG {
 public:
  //! Fill the buffer with cryptographic randomness that is meant to remain private (e.g., for key generation).
  static void FillPrivate(Buffer b);
  //! Fill the buffer with cryptographic randomness that is meant to be public (e.g., for nonces).
  static void FillPublic(Buffer b);

 private:
  static void Init();
};

/**
 * AES-GCM key for encryption, decryption and derivation of new keys.
 */
class Key {
 public:
  static constexpr size_t kSizeTag = 128 / 8;
  static constexpr size_t kSizeKey = 128 / 8;

  //! Generate new key using RNG.
  Key();
  //! Set key directly.
  explicit Key(std::vector<uint8_t> rk);
  Key(Key&& other) noexcept;

  // Copy ctor and operator= are deleted, because we don't want copied keys (only references and derivates).
  Key(const Key&) = delete;
  Key operator=(const Key&) = delete;

  //! Derive new key from current using HKDF with given salt and optional additional data (info).
  Key Derive(CBuffer salt, CBuffer info) const;

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
  bool Decrypt(CBuffer ciphertext, CBuffer iv, CBuffer aad, CBuffer tag, Buffer plaintext) const;

  //! Decrypt without AAD.
  bool Decrypt(CBuffer ciphertext, CBuffer iv, CBuffer tag, Buffer plaintext) const;

  //! Decrypt with AAD only.
  bool Decrypt(CBuffer iv, CBuffer aad, CBuffer tag) const;

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
  void Encrypt(CBuffer plaintext, CBuffer iv, CBuffer aad, Buffer tag, Buffer ciphertext) const;

  //! Encrypt without AAD.
  void Encrypt(CBuffer plaintext, CBuffer iv, Buffer tag, Buffer ciphertext) const;

  //! Encrypt with AAD only. This can be used to protect the integrity of plaintext.
  void Encrypt(CBuffer iv, CBuffer aad, Buffer tag) const;

  //! Get fixed key for testing key (FOR TESTING ONLY).
  static Key GetTestKey() {
    return Key{std::vector<uint8_t>(kSizeKey)};
  }

  static constexpr size_t kDefaultSizeIv = 12;

 private:
  std::vector<uint8_t> rk_;
#ifndef NDEBUG
  // Used for detecting duplicated encryption IVs during testing
  mutable std::set<std::vector<uint8_t>> seen_enc_ivs_;
  mutable std::mutex m_;
#endif
};

using Tag = std::array<uint8_t, Key::kSizeTag>;

}  // namespace crypto
}  // namespace edgeless
