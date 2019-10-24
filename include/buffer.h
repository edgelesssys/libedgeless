// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Adapted from https://github.com/microsoft/CCF

#pragma once
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

template <typename T>
struct Array
{
  // pointer to the buffer
  T* p;
  // number of elements
  size_t n;
  auto size() const
  {
    return n * sizeof(T);
  }

  decltype(auto) data() const
  {
    return p;
  }

  constexpr Array() : p(nullptr), n(0) {}
  constexpr Array(T* p, size_t n) : p(p), n(n) {}

  Array(const std::string& s) :
    p(reinterpret_cast<decltype(p)>(s.data())),
    n(s.size())
  {}

  // conversion from containers
  template<typename C>
  Array(C& c) : p(c.data()), n(c.size()) {}
  template<typename C>
  Array(const C& c) : p(c.data()), n(c.size()) {}

  template <typename U, typename V = void>
  using ENABLE_CTOR = std::enable_if_t<std::is_convertible<U*, T*>::value, V>;
  template <typename U, typename = ENABLE_CTOR<U>>
  Array(const Array<U>& b) : p(b.p), n(b.n)
  {}

  bool operator==(const Array<T>& that) const
  {
    return (that.n == n) && (that.p == p);
  }

  bool operator!=(const Array<T>& that) const
  {
    return !(*this == that);
  }

  using T_NON_CONST = std::remove_const_t<T>;
  explicit operator std::vector<T_NON_CONST>() const
  {
    return {p, p + n};
  }
};

template <typename T>
using CArray = Array<const T>;
using Buffer = Array<uint8_t>;
using CBuffer = Array<const uint8_t>;