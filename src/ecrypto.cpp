#include "ecrypto.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <immintrin.h> // _rdrand64_step() 
#include <assert.h>

namespace crypto { 

Key::Key() : rk_(kSizeKey) {
  // initialize rk_ using _rdrand64_step()
  const auto p = reinterpret_cast<unsigned long long*>(rk_.data());
  const auto n_calls = rk_.size() / sizeof(*p);
  for (auto i = 0ul; i < n_calls; i++)
    for (auto tries = 0u; !_rdrand64_step(p + i); tries++)
      if (tries >= kMaxRetriesRand)
        throw crypto::Error("RDRAND failed to produce randomness");
}

struct KCtx {
  EVP_PKEY_CTX* const p = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  ~KCtx() { EVP_PKEY_CTX_free(p); }
};

Key Key::derive(CBuffer nonce) const {
  KCtx ctx; 
  if (EVP_PKEY_derive_init(ctx.p) <= 0)
    throw crypto::Error("Failed to init HKDF");

  if (EVP_PKEY_CTX_hkdf_mode(ctx.p, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0)
    throw crypto::Error("Failed to set HKDF to extract-only mode");

  if (EVP_PKEY_CTX_set_hkdf_md(ctx.p, EVP_sha256()) <= 0)
    throw crypto::Error("Failed to set MD for HKDF");

  if (EVP_PKEY_CTX_set1_hkdf_key(ctx.p, rk_.data(), rk_.size()) <= 0)
    throw crypto::Error("Failed to set key for HKDF");
  
  if (EVP_PKEY_CTX_set1_hkdf_salt(ctx.p, nonce.p, nonce.size()) <= 0)
    throw crypto::Error("Failed to set salt for HKDF");

  std::vector<uint8_t> buf(32); // output of SHA256 HMAC is 256-bit
  size_t size_buf = buf.size();
  if (EVP_PKEY_derive(ctx.p, buf.data(), &size_buf) <= 0)
    throw crypto::Error("Failed to derive key");
  assert(size_buf == buf.size());
  
  buf.resize(kSizeKey);
  return buf;
}

struct CCtx {
  EVP_CIPHER_CTX* const p = EVP_CIPHER_CTX_new();
  ~CCtx() { EVP_CIPHER_CTX_free(p); }
};

bool Key::decrypt(CBuffer ct, CBuffer iv, CBuffer aad, CBuffer tag, Buffer pt) const {
  CCtx ctx;
  // set key and IV
  if (EVP_DecryptInit_ex(ctx.p, EVP_aes_128_gcm(), nullptr, rk_.data(), iv.p) <= 0)
    throw crypto::Error("Failed to init decryption context.");

  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) <= 0)
    throw crypto::Error("Failed to set IV.");
  
  int len;
  // optionally add aad
  if (aad.data())
    if (EVP_DecryptUpdate(ctx.p, nullptr, &len, aad.data(), aad.size()) <= 0) 
      throw crypto::Error("Failed to set AAD.");

  // decrypt
  assert(pt.size() >= ct.size());
  if (ct.data()) {
    if (EVP_DecryptUpdate(ctx.p, pt.data(), &len, ct.data(), ct.size()) <= 0) 
      throw crypto::Error("Failed to set decrypt.");
    assert(len == ct.size());
  }

  // check tag
  assert(tag.size() >= kSizeTag);
  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, kSizeTag, const_cast<uint8_t*>(tag.p)) <= 0)
    throw crypto::Error("Failed to set tag.");

  return EVP_DecryptFinal_ex(ctx.p, nullptr, &len) > 0;
}

bool Key::decrypt(CBuffer ct, CBuffer iv, CBuffer tag, Buffer pt) const {
  return decrypt(ct, iv, {}, tag, pt);
}

bool Key::decrypt(CBuffer iv, CBuffer aad, CBuffer tag) const {
  return decrypt({}, iv, aad, tag, {});
}

void Key::encrypt(CBuffer pt, CBuffer iv, CBuffer aad, Buffer tag, Buffer ct) const {
  CCtx ctx;
  // set key and IV
  if (EVP_EncryptInit_ex(ctx.p, EVP_aes_128_gcm(), nullptr, rk_.data(), iv.data()) <= 0)
    throw crypto::Error("Failed to init encryption context.");

  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) <= 0)
    throw crypto::Error("Failed to set IV (enc).");

  int len;
  // optionally add aad
  if (aad.data()) 
    if (EVP_EncryptUpdate(ctx.p, nullptr, &len, aad.data(), aad.size()) <= 0) 
      throw crypto::Error("Failed to set AAD (enc).");

  // encrypt
  assert(ct.size() >= pt.size());
  if (pt.data()) {
    if (EVP_EncryptUpdate(ctx.p, ct.data(), &len, pt.data(), pt.size()) <= 0) 
      throw crypto::Error("Failed to encrypt.");
    assert(len == pt.size());
  }

  if (EVP_EncryptFinal_ex(ctx.p, nullptr, &len) <= 0)
    throw crypto::Error("Failed to finalize encryption.");

  // get tag
  assert(tag.size() >= kSizeTag);
  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, kSizeTag, const_cast<uint8_t*>(tag.data())) <= 0)
    throw crypto::Error("Failed to get tag.");
}

void Key::encrypt(CBuffer pt, CBuffer iv, Buffer tag, Buffer ct) const {
  encrypt(pt, iv, {}, tag, ct);
}

void Key::encrypt(CBuffer iv, CBuffer aad, Buffer tag) const {
  encrypt({}, iv, aad, tag, {});
}

}  // namespace crypto