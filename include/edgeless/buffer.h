#pragma once
#include <span.h>

namespace edgeless {

using Buffer = tcb::span<uint8_t>;
using CBuffer = tcb::span<const uint8_t>;

template<typename T>
Buffer ToBuffer(T& v) {
  return {reinterpret_cast<uint8_t*>(&v), sizeof(v)};
}

template<typename T>
CBuffer ToCBuffer(const T& v) {
  return {reinterpret_cast<const uint8_t*>(&v), sizeof(v)};
}

}  // namespace edgeless