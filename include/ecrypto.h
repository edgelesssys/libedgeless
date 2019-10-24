#pragma once
#include <array>
#include <vector>
#include <exception>
#include "buffer.h"

namespace crypto {

struct Error : public std::logic_error {
  using logic_error::logic_error;
};

/**
 * AES-GCM key for encryption, decryption and derivation of new keys.
 * Relies on CBuffer, which is a small template class that containers of uint8_t auto-convert to.
 */
class Key {
public:
  static constexpr size_t kSizeTag = 128 / 8;
  static constexpr size_t kSizeKey = 128 / 8;

  //! Generate new key using Intel instruction RDRAND.
  Key();
  //! Set key directly.
  Key(std::vector<uint8_t> rk) : rk_(std::move(rk)) {}
  Key(const Key&) = delete;

  //! Derive new key from current using a given nonce/salt.
  Key derive(CBuffer nonce) const;

  /**
   * Decrypt with AAD.
   * 
   * @param ct ciphertext buffer
   * @param iv initialization vector buffer
   * @param aad additional authenticated data buffer
   * @param tag tag buffer; serves as MAC
   * @param pt plaintext buffer (out)
   * May be the same as ct for in-place decryption.
   * @return true Decryption succeeded; the tag was valid for the given iv/ct combination.
   * @return false The tag was invalid or other error.
   */
  bool decrypt(CBuffer ct, CBuffer iv, CBuffer aad, CBuffer tag, Buffer pt) const;

  //! Decrypt without AAD.
  bool decrypt(CBuffer ct, CBuffer iv, CBuffer tag, Buffer pt) const;

  //! Decrypt with AAD only.
  bool decrypt(CBuffer iv, CBuffer aad, CBuffer tag) const;

  /**
   * Encrypt with AAD.
   * 
   * @param pt plaintext buffer
   * @param iv initialization vector buffer
   * MUST NEVER repeat for an encryption key!
   * @param aad additional authenticated data buffer
   * @param tag tag buffer (out); serves as MAC
   * @param ct ciphertext buffer (out)
   * May be the same as pt for in-place encryption.
   * @return true success
   * @return false error
   */
  bool encrypt(CBuffer pt, CBuffer iv, CBuffer aad, Buffer tag, Buffer ct) const;

  //! Encrypt without AAD.
  bool encrypt(CBuffer pt, CBuffer iv, Buffer tag, Buffer ct) const;

  //! Encrypt with AAD only. This can be used to protect the integrity of plaintext.
  bool encrypt(CBuffer iv, CBuffer aad, Buffer tag) const;

protected:
  static constexpr auto kMaxRetriesRand = 8u;
  std::vector<uint8_t> rk_;
};

using Tag = std::array<uint8_t, Key::kSizeTag>;

}  // namespace crypto