#include <gtest/gtest.h>
#include "crypto.h"

using namespace std;
using namespace edgeless::crypto;

TEST(Key, enc_dec) {
  constexpr auto size_v = 1000ul;
  const vector<uint8_t> pt_in(size_v, 'a'), iv(12, 'b');
  vector<uint8_t> ct(size_v), pt_out(size_v);

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

TEST(Key, enc_dec_with_aad) {
  constexpr auto size_v = 123ul;
  const vector<uint8_t> pt_in(size_v, 'a'), iv(66, 'b');
  vector<uint8_t> ct(size_v), pt_out(size_v);

  vector<uint8_t> aad(999, 'a');

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
  constexpr auto size_v = 123ul;
  const vector<uint8_t> iv(12, 'b');

  vector<uint8_t> aad(777, 'a');

  const Key key;
  Tag tag;

  ASSERT_NO_THROW(key.Encrypt(iv, aad, tag));
  ASSERT_TRUE(key.Decrypt(iv, aad, tag));

  // modify aad and try again
  aad[aad.size() / 2] ^= 1;
  ASSERT_FALSE(key.Decrypt(iv, aad, tag));
}

TEST(Key, derive_key) {
  const Key k0;
  vector<uint8_t> nonce(200, 'n');
  auto k1 = k0.Derive(nonce);

  constexpr auto size_v = 1000ul;
  const vector<uint8_t> pt_in(size_v, 'a'), iv(12, 'b');
  vector<uint8_t> ct(size_v), pt_out(size_v);

  Tag tag;
  ASSERT_NO_THROW(k1.Encrypt(pt_in, iv, tag, ct));
  // attempt to decrypt with parent key
  ASSERT_FALSE(k0.Decrypt(ct, iv, tag, pt_out));
  ASSERT_TRUE(k1.Decrypt(ct, iv, tag, pt_out));
}