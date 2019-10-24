# Lib Edgeless

This C++ library contains utility modules that are meant to be re-used in different projects. Currently, the following modules are available:

* **ecrypto**: a small wrapper around *OpenSSL EVP*, which we use in *RocksDB* for AES-GCM encryption and key derivation.

## Building

```bash
git submodule init
git submodule update --recursive
mkdir build
cd build
cmake ..
make
```

## Testing

```bash
cd build
ctest
```