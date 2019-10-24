#include "ecrypto.h"
#include <gtest/gtest.h>

using namespace std;

TEST(Key, basic) {
  const vector<uint8_t> pt(1000, 'a');
  const vector<uint8_t> iv(100, 'b');
  decltype(auto) ct = pt;
  crypto::Key key;
  crypto::Tag tag;
  EXPECT_TRUE(key.encrypt(pt, iv, tag));
}