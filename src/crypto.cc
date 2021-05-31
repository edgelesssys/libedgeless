#include "crypto.h"

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <cassert>
#include <mutex>

// disable LSAN because of leak in RNG::Init
#ifndef __SANITIZE_ADDRESS__
#ifdef __has_feature
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__
#endif
#endif
#endif
#ifdef __SANITIZE_ADDRESS__
extern "C" const char* __asan_default_options() { return "detect_leaks=0"; }
#endif

namespace edgeless::crypto {

void RNG::Init() {
  static std::mutex m;
  static std::atomic<bool> initialized;

  if (initialized.load())
    return;
  const std::lock_guard lg(m);
  if (initialized.load())
    return;

  /* TODO: according to ASAN, this leaks an ENGINE object.
  Not sure how to deallocate it. ENGINE_cleanup() etc don't help. */
  ENGINE_load_rdrand();
  const auto eng = ENGINE_by_id("rdrand");
  if (!eng) {
    throw crypto::Error("Failed to get RDRAND engine");
  }
  // ENGINEs are ref counted
  if (!ENGINE_init(eng)) {
    throw crypto::Error("Failed to init engine");
  }
  const auto succ = ENGINE_set_default_RAND(eng);
  ENGINE_finish(eng);
  if (!succ) {
    throw crypto::Error("Failed to set engine");
  }
  initialized = true;
}

void RNG::FillPublic(Buffer b) {
  Init();
  if (RAND_bytes(b.data(), b.size()) != 1)
    throw crypto::Error("Failed to generate public random bytes");
}

void RNG::FillPrivate(Buffer b) {
  Init();
  if (RAND_priv_bytes(b.data(), b.size()) != 1)
    throw crypto::Error("Failed to generate private random bytes");
}

Key::Key() : rk_(kSizeKey) {
  RNG::FillPrivate(rk_);
}

Key::Key(std::vector<uint8_t> rk) : rk_(std::move(rk)) {
  assert(rk_.size() >= kSizeKey);
}

Key::Key(Key&& other) noexcept : rk_(std::move(other.rk_)) {
}

struct KCtx {
  EVP_PKEY_CTX* const p;
  KCtx() : p(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr)) {
    if (!p)
      throw crypto::Error("Failed to allocate PKEY CTX");
  }
  ~KCtx() { EVP_PKEY_CTX_free(p); }
};

Key Key::Derive(CBuffer nonce) const {
  KCtx ctx;
  if (EVP_PKEY_derive_init(ctx.p) <= 0)
    throw crypto::Error("Failed to init HKDF");

  if (EVP_PKEY_CTX_hkdf_mode(ctx.p, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0)
    throw crypto::Error("Failed to set HKDF to extract-only mode");

  if (EVP_PKEY_CTX_set_hkdf_md(ctx.p, EVP_sha256()) <= 0)
    throw crypto::Error("Failed to set MD for HKDF");

  if (EVP_PKEY_CTX_set1_hkdf_key(ctx.p, rk_.data(), rk_.size()) <= 0)
    throw crypto::Error("Failed to set key for HKDF");

  if (EVP_PKEY_CTX_set1_hkdf_salt(ctx.p, nonce.data(), nonce.size()) <= 0)
    throw crypto::Error("Failed to set salt for HKDF");

  std::vector<uint8_t> buf(32);  // output of SHA256 HMAC is 256-bit
  size_t size_buf = buf.size();
  if (EVP_PKEY_derive(ctx.p, buf.data(), &size_buf) <= 0)
    throw crypto::Error("Failed to derive key");
  assert(size_buf == buf.size());

  buf.resize(kSizeKey);
  return Key{buf};
}

struct CCtx {
  EVP_CIPHER_CTX* const p;

  CCtx() : p(EVP_CIPHER_CTX_new()) {
    if (!p)
      throw crypto::Error("Could not allocate CIPHER_CTX");
  }
  ~CCtx() { EVP_CIPHER_CTX_free(p); }
};

template <typename F_INIT>
void Init(const F_INIT f_init, const CCtx& ctx, const std::vector<uint8_t>& rk, const CBuffer iv) {
  assert(rk.size() == Key::kSizeKey);
  // in case of a default IV size, we can set everything up in one call
  if (iv.size() == Key::kDefaultSizeIv) {
    if (f_init(ctx.p, EVP_aes_128_gcm(), nullptr, rk.data(), iv.data()) <= 0)
      throw crypto::Error("Failed to init context (enc, default IV size).");
  } else {
    assert(!iv.empty());
    if (f_init(ctx.p, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) <= 0)
      throw crypto::Error("Failed to init context.");
    if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) <= 0)
      throw crypto::Error("Failed to set IV length.");
    if (f_init(ctx.p, nullptr, nullptr, rk.data(), iv.data()) <= 0)
      throw crypto::Error("Failed to set key and IV.");
  }
}

bool Key::Decrypt(CBuffer ciphertext, CBuffer iv, CBuffer aad, CBuffer tag, Buffer plaintext) const {
  CCtx ctx;
  Init(EVP_DecryptInit_ex, ctx, rk_, iv);

  // optionally add aad
  if (!aad.empty()) {
    int aad_s = 0;
    if (EVP_DecryptUpdate(ctx.p, nullptr, &aad_s, aad.data(), aad.size()) <= 0)
      throw crypto::Error("Failed to set AAD.");
    assert(static_cast<size_t>(aad_s) == aad.size());
  }

  // decrypt
  assert(plaintext.size() >= ciphertext.size());
  if (!ciphertext.empty()) {
    int plaintext_s = 0;
    if (EVP_DecryptUpdate(ctx.p, plaintext.data(), &plaintext_s, ciphertext.data(), ciphertext.size()) <= 0)
      throw crypto::Error("Failed to set decrypt.");
    assert(static_cast<size_t>(plaintext_s) == ciphertext.size());
  }

  // check tag
  assert(tag.size() >= kSizeTag);
  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, kSizeTag, const_cast<uint8_t*>(tag.data())) <= 0)
    throw crypto::Error("Failed to set tag.");

  int final_s = 0;
  const auto tag_valid = EVP_DecryptFinal_ex(ctx.p, plaintext.end(), &final_s) > 0;
  assert(!final_s);
  return tag_valid;
}

bool Key::Decrypt(CBuffer ciphertext, CBuffer iv, CBuffer tag, Buffer plaintext) const {
  return Decrypt(ciphertext, iv, {}, tag, plaintext);
}

bool Key::Decrypt(CBuffer iv, CBuffer aad, CBuffer tag) const {
  return Decrypt({}, iv, aad, tag, {});
}

void Key::Encrypt(CBuffer plaintext, CBuffer iv, CBuffer aad, Buffer tag, Buffer ciphertext) const {
#ifndef NDEBUG
  {
    std::lock_guard guard(m_);
    const std::vector<uint8_t> ivv(iv.data(), iv.data() + iv.size());
    if (seen_enc_ivs_.find(ivv) != seen_enc_ivs_.end())
      throw crypto::Error("DEBUG: reuse of IV during encryption.");
    seen_enc_ivs_.insert(ivv);
  }
#endif

  CCtx ctx;
  Init(EVP_EncryptInit_ex, ctx, rk_, iv);

  // optionally add aad
  if (!aad.empty()) {
    int aad_s = 0;
    if (EVP_EncryptUpdate(ctx.p, nullptr, &aad_s, aad.data(), aad.size()) <= 0)
      throw crypto::Error("Failed to set AAD (enc).");
    assert(static_cast<size_t>(aad_s) == aad.size());
  }

  // encrypt
  assert(ciphertext.size() >= plaintext.size());
  if (!plaintext.empty()) {
    int ciphertext_s = 0;
    if (EVP_EncryptUpdate(ctx.p, ciphertext.data(), &ciphertext_s, plaintext.data(), plaintext.size()) <= 0)
      throw crypto::Error("Failed to encrypt.");
    assert(static_cast<size_t>(ciphertext_s) == plaintext.size());
  }

  int final_s = 0;
  if (EVP_EncryptFinal_ex(ctx.p, ciphertext.end(), &final_s) <= 0)
    throw crypto::Error("Failed to finalize encryption.");
  assert(!final_s);

  // get tag
  assert(tag.size() >= kSizeTag);
  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, kSizeTag, const_cast<uint8_t*>(tag.data())) <= 0)
    throw crypto::Error("Failed to get tag.");
}

void Key::Encrypt(CBuffer plaintext, CBuffer iv, Buffer tag, Buffer ciphertext) const {
  Encrypt(plaintext, iv, {}, tag, ciphertext);
}

void Key::Encrypt(CBuffer iv, CBuffer aad, Buffer tag) const {
  Encrypt({}, iv, aad, tag, {});
}

}  // namespace edgeless::crypto
