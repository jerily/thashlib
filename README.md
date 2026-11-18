# thashlib

Hashes, HMAC-SHA256, secure random bytes and hexadecimal conversion for Tcl.
The C extension uses OpenSSL 3's libcrypto and Tcl stubs. It supports Tcl 8.6
and Tcl 9.x, with separate builds for each Tcl major version.

## Install with ttrek

If you do not have the ttrek client, get it from [ttrek.sh](https://ttrek.sh).
Then install the package in your project:

```sh
ttrek install thashlib
```

```tcl
package require thashlib 0.1.1
set bytes [encoding convertto utf-8 "Hello, world!"]
puts [::thashlib::sha256 -hex $bytes]
```

## Commands

| Command | Result |
| --- | --- |
| `::thashlib::random_bytes num_bytes` | The requested nonnegative number of cryptographically secure random bytes. |
| `::thashlib::sha1 ?-hex? bytes` | 20-byte SHA-1 digest. |
| `::thashlib::sha256 ?-hex? bytes` | 32-byte SHA-256 digest. |
| `::thashlib::sha384 ?-hex? bytes` | 48-byte SHA-384 digest (since 0.1.1). |
| `::thashlib::sha512 ?-hex? bytes` | 64-byte SHA-512 digest. |
| `::thashlib::md5 ?-hex? bytes` | 16-byte MD5 digest. |
| `::thashlib::hmac_sha256 ?-hex? key bytes` | 32-byte HMAC-SHA256 using the supplied key bytes. |
| `::thashlib::constant_time_equal a b` | Byte-array equality using OpenSSL CRYPTO_memcmp for equal lengths; unequal lengths return false (since 0.1.1). |
| `::thashlib::hex_encode bytes` | Lowercase hexadecimal string without separators. |
| `::thashlib::hex_decode hex_encoded_string` | Decoded bytes; accepts uppercase or lowercase digits. |

Digest and HMAC commands return Tcl byte arrays by default; `-hex` returns
lowercase hexadecimal instead, like Python hashlib's `hexdigest()`. Random and
decode results are Tcl byte arrays. A sole hash argument named `-hex` is treated
as data; an HMAC key named `-hex` is likewise data when followed by just a message. All byte arguments
are taken as bytes without implicit UTF-8 encoding: use `encoding convertto utf-8`
when hashing text. Empty inputs and zero-length random output are supported.
Hex decoding requires an even number of digits and rejects separators,
whitespace, embedded NULs and non-hexadecimal characters.

```tcl
set key [::thashlib::random_bytes 32]
set mac [::thashlib::hmac_sha256 $key [encoding convertto utf-8 "message"]]
puts [::thashlib::hex_encode $mac]
puts [binary encode base64 -maxlen 0 [::thashlib::md5 $bytes]]
```

OpenSSL failures raise Tcl errors with error code `THASHLIB OPENSSL`.
Algorithm availability follows the application's OpenSSL provider configuration.
Invalid hexadecimal input uses `THASHLIB HEX`; invalid random lengths or
oversized hexadecimal output use `THASHLIB LENGTH`.

## Build and test

Requires a C11 compiler, CMake 3.22.1+, OpenSSL 3.0+ development files and Tcl
headers/stub library. Point CMake at the Tcl installation you intend to use:

```sh
cmake -S . -B build \
  -DTCL_INCLUDE_PATH=/your/tcl/include \
  -DTCL_LIBRARY_DIR=/your/tcl/lib \
  -DTCL_TCLSH=/your/tcl/bin/tclsh9.1 \
  -DCMAKE_INSTALL_PREFIX=/your/prefix
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build
```

Set `OPENSSL_ROOT_DIR` for a non-system OpenSSL installation. Tests include
digest and HMAC vectors, binary data, hash block boundaries, input errors and
hexadecimal round trips. Set `BUILD_TESTING=OFF` when building without a runnable
target Tcl interpreter, such as during cross compilation.

For static embedding, configure with `-DBUILD_SHARED_LIBS=OFF`. Link the resulting
archive with Tcl and OpenSSL libcrypto and register `Thashlib_Init` with your Tcl
application. Static installs omit the dynamic-loading `pkgIndex.tcl`. The static
test executable exercises the same command tests through an embedded interpreter.

## License

MIT; see [LICENSE](LICENSE).
