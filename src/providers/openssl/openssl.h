#pragma once

#include <array>
#include <memory>
#include <openssl/hmac.h>
#include <provider.h>

namespace sframe {
namespace provider {
namespace openssl {

struct openssl_error : std::runtime_error
{
  openssl_error();
};

using scoped_hmac_ctx = std::unique_ptr<HMAC_CTX, decltype(&HMAC_CTX_free)>;

struct OpenSSLProvider : Provider
{
  // Create an OpenSSL provider for the given cipher suite.
  OpenSSLProvider(CipherSuite suite);

  ///
  /// Information about algorithms
  ///
  std::size_t cipher_digest_size() const override;
  std::size_t cipher_key_size() const override;
  std::size_t cipher_nonce_size() const override;

  ///
  /// HMAC and HKDF
  ///
  bytes hkdf_extract(const bytes& salt,
                     const bytes& ikm) const override;
  bytes hkdf_expand(const bytes& secret,
                    const bytes& info,
                    std::size_t size) const override;
  bool is_ctr_hmac() const override;

  ///
  /// AEAD Algorithms
  ///
  output_bytes seal(const bytes& key,
                    const bytes& nonce,
                    output_bytes ct,
                    input_bytes aad,
                    input_bytes pt) const override;
  output_bytes open(const bytes& key,
                    const bytes& nonce,
                    output_bytes pt,
                    input_bytes aad,
                    input_bytes ct) const override;

private:
  struct HMAC
  {
    HMAC(CipherSuite suite, input_bytes key);
    void write(input_bytes data);
    input_bytes digest();

    scoped_hmac_ctx ctx;
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> md;
  };

  bytes hmac_for_hkdf(input_bytes key, input_bytes data) const;
  output_bytes seal_ctr(const bytes& key,
                        const bytes& nonce,
                        output_bytes ct,
                        input_bytes aad,
                        input_bytes pt) const;
  output_bytes open_ctr(const bytes& key,
                        const bytes& nonce,
                        output_bytes pt,
                        input_bytes aad,
                        input_bytes ct) const;

protected:
  const CipherSuite suite;
};
}
}
}