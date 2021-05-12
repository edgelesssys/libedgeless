# Lib Edgeless

This C++ library contains utility modules that are meant to be re-used in different projects. Currently, the following modules are available:

* **crypto**: a small wrapper around *OpenSSL EVP*, which we use in *RocksDB* for AES-GCM encryption and key derivation.

## Build

```bash
sudo apt install clang-tidy-10
mkdir build
cd build
cmake ..
make
ctest
```
