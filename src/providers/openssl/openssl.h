#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <openssl/hmac.h>
#include <provider.h>

namespace sframe {
namespace provider {
namespace openssl {

using CipherSuite = std::uint16_t;
const CipherSuite AES_CM_128_HMAC_SHA256_4 = 1;
const CipherSuite AES_CM_128_HMAC_SHA256_8 = 2;
const CipherSuite AES_GCM_128_SHA256 = 3;
const CipherSuite AES_GCM_256_SHA512 = 4;
const CipherSuite supported_ciphers[4] = { AES_CM_128_HMAC_SHA256_4,
                                           AES_CM_128_HMAC_SHA256_8,
                                           AES_GCM_128_SHA256,
                                           AES_GCM_256_SHA512 };

struct openssl_error : std::runtime_error
{
  openssl_error();
};

using scoped_hmac_ctx = std::unique_ptr<HMAC_CTX, decltype(&HMAC_CTX_free)>;

struct OpenSSLProvider : Provider
{
  ///
  /// Information about algorithms
  ///
  std::set<CipherSuite> supported_ciphersuites() const override;
  std::size_t cipher_digest_size(CipherSuite cipher) const override;
  std::size_t cipher_key_size(CipherSuite cipher) const override;
  std::size_t cipher_nonce_size(CipherSuite cipher) const override;

  ///
  /// HMAC and HKDF
  ///
  bytes hkdf_extract(CipherSuite cipher,
                     const bytes& salt,
                     const bytes& ikm) const override;
  bytes hkdf_expand(CipherSuite cipher,
                    const bytes& secret,
                    const bytes& info,
                    std::size_t size) const override;

  ///
  /// AEAD Algorithms
  ///
  output_bytes seal(CipherSuite cipher,
                    const bytes& key,
                    const bytes& nonce,
                    output_bytes ct,
                    input_bytes aad,
                    input_bytes pt) const override;
  output_bytes open(CipherSuite cipher,
                    const bytes& key,
                    const bytes& nonce,
                    output_bytes pt,
                    input_bytes aad,
                    input_bytes ct) const override;

private:
  bytes hmac_for_hkdf(CipherSuite cipher,
                      input_bytes key,
                      input_bytes data) const;
  output_bytes seal_ctr(CipherSuite cipher,
                        const bytes& key,
                        const bytes& nonce,
                        output_bytes ct,
                        input_bytes aad,
                        input_bytes pt) const;
  output_bytes open_ctr(CipherSuite cipher,
                        const bytes& key,
                        const bytes& nonce,
                        output_bytes pt,
                        input_bytes aad,
                        input_bytes ct) const;
};

struct HMAC
{
  HMAC(CipherSuite suite, input_bytes key);
  void write(input_bytes data);
  input_bytes digest();

  scoped_hmac_ctx ctx;
  std::array<std::uint8_t, EVP_MAX_MD_SIZE> md;
};

}
}
}