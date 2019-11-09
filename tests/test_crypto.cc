#include <algorithm>
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

TEST(Key, enc_dec_inplace) {
  const vector<uint8_t> ref(456, 'a'), iv(12, 'b');
  vector<uint8_t> buf = ref; 
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

// replicate an error from rocksdb
TEST(Key, aad_only_rocksdb_footer) {
  static constexpr array<uint8_t, 12> iv{"footer12345"};
  const vector<uint8_t> nonce(20, 'n'), raw_key{73, 213, 224, 7, 127, 55, 164, 221, 241, 22, 90, 224, 163, 17, 23, 63};
  const Key key_enc(raw_key), key_dec(raw_key);

  // replicate footer layout
  vector<uint8_t> buf = {237, 166, 2, 34, 175, 159, 2, 159, 2};
  buf.resize(56);
  edgeless::Buffer aad(buf.data(), 40);
  edgeless::Buffer tag(aad.end(), Key::kSizeTag);

  ASSERT_NO_THROW(key_enc.Encrypt(iv, aad, tag));
  ASSERT_TRUE(key_dec.Decrypt(iv, aad, tag));

  // modify aad and try again
  aad.data()[aad.size() / 2] ^= 1;
  ASSERT_FALSE(key_dec.Decrypt(iv, aad, tag));
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