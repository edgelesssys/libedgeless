#include <ecrypto.h>

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

Key Key::derive(const uint8_t* nonce, const size_t size_nonce) const {
  KCtx ctx; 
  if (EVP_PKEY_derive_init(ctx.p) <= 0)
    throw crypto::Error("Failed to init HKDF");

  if (EVP_PKEY_CTX_hkdf_mode(ctx.p, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0)
    throw crypto::Error("Failed to set HKDF to extract-only mode");

  if (EVP_PKEY_CTX_set_hkdf_md(ctx.p, EVP_sha256()) <= 0)
    throw crypto::Error("Failed to set MD for HKDF");

  if (EVP_PKEY_CTX_set1_hkdf_key(ctx.p, rk_.data(), rk_.size()) <= 0)
    throw crypto::Error("Failed to set key for HKDF");
  
  if (EVP_PKEY_CTX_set1_hkdf_salt(ctx.p, nonce, size_nonce) <= 0)
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

bool Key::decrypt(const uint8_t* ct, const size_t size_ct, const uint8_t* iv,
                  const size_t size_iv, const uint8_t* aad,
                  const size_t size_aad, const uint8_t* tag,
                  uint8_t* pt) const {
  CCtx ctx;
  // set key and IV
  if (EVP_DecryptInit_ex(ctx.p, EVP_aes_128_gcm(), nullptr, rk_.data(), iv) <= 0)
    return false;

  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, size_iv, nullptr) <= 0)
    return false;
  // decrypt
  int len;
  if (EVP_DecryptUpdate(ctx.p, nullptr, &len, aad, size_aad) <= 0) 
    return false;

  if (EVP_DecryptUpdate(ctx.p, pt, &len, ct, size_ct) <= 0) 
    return false;

  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, kSizeTag,
                           const_cast<uint8_t*>(tag)) <= 0)
    return false;

  return EVP_DecryptFinal_ex(ctx.p, nullptr, &len);
}

bool Key::decrypt(const uint8_t* ct, const size_t size_ct, const uint8_t* iv,
                  const size_t size_iv, const uint8_t* tag, uint8_t* pt) const {
  return decrypt(ct, size_ct, iv, size_iv, nullptr, 0, tag, pt);
}

bool Key::decrypt(const uint8_t* iv, const size_t size_iv, const uint8_t* aad,
                  size_t size_aad, const uint8_t* tag) const {
  return decrypt(nullptr, 0, iv, size_iv, aad, size_aad, tag, nullptr);
}

bool Key::encrypt(const uint8_t* pt, const size_t size_pt, const uint8_t* iv,
                  const size_t size_iv, const uint8_t* aad,
                  const size_t size_aad, uint8_t* tag, uint8_t* ct) const {
  CCtx ctx;
  // set key and IV
  if (EVP_EncryptInit_ex(ctx.p, EVP_aes_128_gcm(), nullptr, rk_.data(), iv) <= 0)
    return false;

  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, size_iv, nullptr) <= 0)
    return false;
  // encrypt
  int len;
  if (EVP_EncryptUpdate(ctx.p, nullptr, &len, aad, size_aad) <= 0) 
    return false;

  if (EVP_EncryptUpdate(ctx.p, ct, &len, pt, size_pt) <= 0) 
    return false;

  if (!EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, kSizeTag, tag) <= 0)
    return false;

  return EVP_EncryptFinal_ex(ctx.p, nullptr, &len);
}

bool Key::encrypt(const uint8_t* pt, const size_t size_pt, const uint8_t* iv,
                  const size_t size_iv, uint8_t* tag, uint8_t* ct) const {
  return encrypt(pt, size_pt, iv, size_iv, nullptr, 0, tag, ct);
}

bool Key::encrypt(const uint8_t* iv, const size_t size_iv, const uint8_t* aad,
                  const size_t size_aad, uint8_t* tag) const {
  return encrypt(nullptr, 0, iv, size_iv, aad, size_aad, tag, nullptr);
}

}  // namespace crypto