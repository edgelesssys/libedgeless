#include "ecrypto.h"
#include <gtest/gtest.h>
#include <algorithm>

using namespace std;

TEST(Key, basic_enc_dec) {
  constexpr auto size_v = 1000ul;
  const vector<uint8_t> pt_in(size_v, 'a'), iv(12, 'b');
  vector<uint8_t> ct(size_v), pt_out(size_v);
  
  crypto::Key key;
  crypto::Tag tag;
  fill(tag.begin(), tag.end(), 't');

  ASSERT_TRUE(key.encrypt(pt_in, iv, tag, ct));
  ASSERT_TRUE(key.decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);

  // modify tag and try again
  tag[0] ^= 1;
  ASSERT_FALSE(key.decrypt(ct, iv, tag, pt_out));
  EXPECT_EQ(pt_in, pt_out);
}