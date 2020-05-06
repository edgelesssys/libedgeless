#include <algorithm>
#include <gtest/gtest.h>
#include "crypto.h"

using namespace std;
using namespace edgeless::crypto;

using VB = vector<uint8_t>;

TEST(Key, enc_dec) {
  constexpr auto size_v = 1000ul;
  const VB pt_in(size_v, 'a'), iv(12, 'b');
  VB ct(size_v), pt_out(size_v);

  const Key key;
  Tag tag;
  tag.fill('t');

  ASSERT_NO_THROW(key.Encrypt(pt_in, iv, tag, ct));
  EXPECT_NE(pt_in, ct);
  ASSERT_TRUE(key.Decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // decrypt again
  ASSERT_TRUE(key.Decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // modify tag and try again
  tag[0] ^= 1;
  ASSERT_FALSE(key.Decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);
}

TEST(Key, enc_dec_2) {
  constexpr auto size_v = 1053ul;
  const VB pt_in(size_v, 'a');
  VB ct_and_tag(size_v + 16), pt_out(size_v);
  VB iv(8);
  fill(iv.begin(), iv.end(), 'x');

  // construct an 8-byte IV where we can change trailing bytes
  edgeless::Buffer ct(ct_and_tag.data(), size_v); 
  edgeless::Buffer tag(ct_and_tag.end().base()-16, 16);

  const Key key;
  ASSERT_NO_THROW(key.Encrypt(pt_in, iv, tag, ct));

  // change bytes trailing iv
  fill(iv.begin() + 8, iv.end(), 'y');
  ASSERT_TRUE(key.Decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // decrypt again
  ASSERT_TRUE(key.Decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // modify tag and try again
  tag[0] ^= 1;
  ASSERT_FALSE(key.Decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);
}

TEST(Key, enc_dec_inplace) {
  const VB ref(456, 'a'), iv(12, 'b');
  VB buf = ref; 
  const Key key;
  Tag tag;

  // encrypt in place
  ASSERT_NO_THROW(key.Encrypt(buf, iv, tag, buf));
  EXPECT_NE(buf, ref);
  // decrypt in place
  ASSERT_TRUE(key.Decrypt(buf, iv, tag, buf));
  EXPECT_EQ(buf, ref);
}

TEST(Key, enc_dec_with_aad) {
  constexpr auto size_v = 123ul;
  const VB pt_in(size_v, 'a'), iv(66, 'b');
  VB ct(size_v), pt_out(size_v);

  VB aad(999, 'a');

  const Key key;
  Tag tag;
  tag.fill('t');

  ASSERT_NO_THROW(key.Encrypt(pt_in, iv, aad, tag, ct));
  EXPECT_NE(pt_in, ct);
  ASSERT_TRUE(key.Decrypt(ct, iv, aad, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // decrypt again
  ASSERT_TRUE(key.Decrypt(ct, iv, aad, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // modify aad and try again
  aad[0] ^= 1;
  ASSERT_FALSE(key.Decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);
}

TEST(Key, aad_only) {
  const VB iv(12, 'b');

  VB aad(777, 'a');

  const Key key;
  Tag tag;

  ASSERT_NO_THROW(key.Encrypt(iv, aad, tag));
  ASSERT_TRUE(key.Decrypt(iv, aad, tag));

  // modify aad and try again
  aad[aad.size() / 2] ^= 1;
  ASSERT_FALSE(key.Decrypt(iv, aad, tag));
}

TEST(Key, reference_vectors) {
  // This test performs authenticated encryption using well-known test vectors
  Key key({0x88, 0xEE, 0x08, 0x7F, 0xD9, 0x5D, 0xA9, 0xFB, 0xF6, 0x72, 0x5A, 0xA9, 0xD7, 0x57, 0xB0, 0xCD});

  const VB plaintext = {0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x00, 0x08};
  
  const VB aad = {0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x88, 0xE5, 0x4D, 0x00, 0x2E, 0x58, 0x49, 0x5C};

  const VB iv = {0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5, 0x00, 0x01, 0x2E, 0x58, 0x49, 0x5C};

  const VB ciphertext_ref = {0xC3, 0x1F, 0x53, 0xD9, 0x9E, 0x56, 0x87, 0xF7, 0x36, 0x51, 0x19, 0xB8, 0x32, 0xD2, 0xAA, 0xE7, 0x07, 0x41, 0xD5, 0x93, 0xF1, 0xF9, 0xE2, 0xAB, 0x34, 0x55, 0x77, 0x9B, 0x07, 0x8E, 0xB8, 0xFE, 0xAC, 0xDF, 0xEC, 0x1F, 0x8E, 0x3E, 0x52, 0x77, 0xF8, 0x18, 0x0B, 0x43, 0x36, 0x1F, 0x65, 0x12, 0xAD, 0xB1, 0x6D, 0x2E, 0x38, 0x54, 0x8A, 0x2C, 0x71, 0x9D, 0xBA, 0x72, 0x28, 0xD8, 0x40};

  const VB tag_ref = {0x88, 0xF8, 0x75, 0x7A, 0xDB, 0x8A, 0xA7, 0x88, 0xD8, 0xF6, 0x5A, 0xD6, 0x68, 0xBE, 0x70, 0xE7};

  VB ciphertext(ciphertext_ref.size()), tag(tag_ref.size());

  ASSERT_NO_THROW(key.Encrypt(plaintext, iv, aad, tag, ciphertext));
  ASSERT_EQ(ciphertext, ciphertext_ref);
  ASSERT_EQ(tag, tag_ref);
}

#ifndef NDEBUG
TEST(Key, check_duplicate_iv) {
  constexpr auto size_v = 1000ul;
  const VB pt_in(size_v, 'a'), iv(12, 'b');
  VB ct(size_v), pt_out(size_v);

  const Key key;
  Tag tag;

  for (int i = 0; i < 10; i++)
    ASSERT_NO_THROW(key.Encrypt(pt_in, {(uint8_t*)&i, sizeof(i)}, tag, ct));

  for (int i = 0; i < 10; i++)
    ASSERT_THROW(key.Encrypt(pt_in, {(uint8_t*)&i, sizeof(i)}, tag, ct), edgeless::crypto::Error);
}

#endif