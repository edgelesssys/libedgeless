#include "ecrypto.h"
#include <gtest/gtest.h>

using namespace std;

TEST(Key, basic) {
    const vector<uint8_t> pt0(1000, 'a');
    const vector<uint8_t> iv(100, 'b');
    
    decltype(auto) pt1 = pt0;

    crypto::Key key;
    vector<uint8_t> tag(16);
    key.encrypt(pt0, iv, tag);
}