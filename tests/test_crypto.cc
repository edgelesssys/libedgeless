#include "crypto.h"
#include <gtest/gtest.h>
#include <algorithm>

using namespace std;

TEST(Key, enc_dec) {
  constexpr auto size_v = 1000ul;
  const vector<uint8_t> pt_in(size_v, 'a'), iv(12, 'b');
  vector<uint8_t> ct(size_v), pt_out(size_v);
  
  crypto::Key key;
  crypto::Tag tag;
  fill(tag.begin(), tag.end(), 't');

  key.encrypt(pt_in, iv, tag, ct);

  ASSERT_NO_THROW(key.encrypt(pt_in, iv, tag, ct));
  EXPECT_NE(pt_in, ct);
  ASSERT_TRUE(key.decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // decrypt again
  ASSERT_TRUE(key.decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // modify tag and try again
  tag[0] ^= 1;
  ASSERT_FALSE(key.decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);
}

TEST(Key, enc_dec_with_aad) {
  constexpr auto size_v = 123ul;
  const vector<uint8_t> pt_in(size_v, 'a'), iv(66, 'b');
  vector<uint8_t> ct(size_v), pt_out(size_v);

  vector<uint8_t> aad(999, 'a');
  
  crypto::Key key;
  crypto::Tag tag;
  fill(tag.begin(), tag.end(), 't');

  ASSERT_NO_THROW(key.encrypt(pt_in, iv, aad, tag, ct));
  EXPECT_NE(pt_in, ct);
  ASSERT_TRUE(key.decrypt(ct, iv, aad, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // decrypt again
  ASSERT_TRUE(key.decrypt(ct, iv, aad, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // modify aad and try again
  aad[0] ^= 1;
  ASSERT_FALSE(key.decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);
}

TEST(Key, aad_only) {
  constexpr auto size_v = 123ul;
  const vector<uint8_t> iv(12, 'b');

  vector<uint8_t> aad(777, 'a');
  
  crypto::Key key;
  crypto::Tag tag;

  ASSERT_NO_THROW(key.encrypt(iv, aad, tag));
  ASSERT_TRUE(key.decrypt(iv, aad, tag));

  // modify aad and try again
  aad[aad.size()/2] ^= 1;
  ASSERT_FALSE(key.decrypt(iv, aad, tag));
}

TEST(Key, derive_key) {
  crypto::Key k0;
  vector<uint8_t> nonce(200, 'n');
  auto k1 = k0.derive(nonce);

  constexpr auto size_v = 1000ul;
  const vector<uint8_t> pt_in(size_v, 'a'), iv(12, 'b');
  vector<uint8_t> ct(size_v), pt_out(size_v);

  crypto::Tag tag;
  ASSERT_NO_THROW(k1.encrypt(pt_in, iv, tag, ct));
  // attempt to decrypt with parent key
  ASSERT_FALSE(k0.decrypt(ct, iv, tag, pt_out));
  ASSERT_TRUE(k1.decrypt(ct, iv, tag, pt_out));
}