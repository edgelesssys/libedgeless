#include "crypto.h"

#include <assert.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace edgeless {
namespace crypto {

std::mutex RNG::m_;
void* RNG::engine_;

void RNG::Init() {
  const std::lock_guard lg(m_);
  if (engine_)
    return;

  ENGINE_load_rdrand();
  const auto eng = ENGINE_by_id("rdrand");
  if (!eng) {
    throw crypto::Error("Failed to get RDRAND engine");
  }
  if (ENGINE_init(eng) != 1) {
    ENGINE_finish(eng);
    throw crypto::Error("Failed to init engine");
  }
  if (ENGINE_set_default(eng, ENGINE_METHOD_RAND) != 1) {
    ENGINE_finish(eng);
    throw crypto::Error("Failed to set engine");
  }
  engine_ = eng;
}

// NOTE: the OpenSSL docs state that the default RAND_DRBG and thus RAND_bytes and RAND_priv_bytes are thread-safe: https://www.openssl.org/docs/man1.1.1/man7/RAND_DRBG.html

bool RNG::FillPublic(Buffer b) {
  if (!engine_)
    Init();

  return RAND_bytes(b.data(), b.size()) == 1;
}

bool RNG::FillPrivate(Buffer b) {
  if (!engine_)
    Init();

  return RAND_priv_bytes(b.data(), b.size()) == 1;
}

void RNG::Cleanup() {
  const std::lock_guard lg(m_);
  if (!engine_)
    return;

  ENGINE_finish(static_cast<ENGINE*>(engine_));
  engine_ = nullptr;
}

Key::Key() : rk_(kSizeKey) {
  if (!RNG::FillPrivate(rk_))
    throw crypto::Error("Failed to generate key");
}

Key::Key(std::vector<uint8_t> rk) : rk_(rk) {
  assert(rk_.size() >= kSizeKey);
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
    assert(iv.size());
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
  if (aad.size()) {
    int aad_s;
    if (EVP_DecryptUpdate(ctx.p, nullptr, &aad_s, aad.data(), aad.size()) <= 0)
      throw crypto::Error("Failed to set AAD.");
    assert(aad_s == aad.size());
  }

  // decrypt
  assert(plaintext.size() >= ciphertext.size());
  if (ciphertext.size()) {
    int plaintext_s;
    if (EVP_DecryptUpdate(ctx.p, plaintext.data(), &plaintext_s, ciphertext.data(), ciphertext.size()) <= 0)
      throw crypto::Error("Failed to set decrypt.");
    assert(plaintext_s == ciphertext.size());
  }

  // check tag
  assert(tag.size() >= kSizeTag);
  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, kSizeTag, const_cast<uint8_t*>(tag.data())) <= 0)
    throw crypto::Error("Failed to set tag.");

  int final_s;
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
  if (aad.size()) {
    int aad_s;
    if (EVP_EncryptUpdate(ctx.p, nullptr, &aad_s, aad.data(), aad.size()) <= 0)
      throw crypto::Error("Failed to set AAD (enc).");
    assert(aad_s == aad.size());
  }

  // encrypt
  assert(ciphertext.size() >= plaintext.size());
  if (plaintext.size()) {
    int ciphertext_s;
    if (EVP_EncryptUpdate(ctx.p, ciphertext.data(), &ciphertext_s, plaintext.data(), plaintext.size()) <= 0)
      throw crypto::Error("Failed to encrypt.");
    assert(ciphertext_s == plaintext.size());
  }

  int final_s;
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

}  // namespace crypto
}  // namespace edgeless