#pragma once

#include <cstdint>
#include <provider.h>

namespace sframe {

using CipherSuiteIdentifier = std::uint16_t;

// Built in cipher suite identifiers.
enum class CipherSuite : CipherSuiteIdentifier
{
  AES_CM_128_HMAC_SHA256_4 = 1,
  AES_CM_128_HMAC_SHA256_8 = 2,
  AES_GCM_128_SHA256 = 3,
  AES_GCM_256_SHA512 = 4,
};

class Cipher
{
public:
  Cipher(CipherSuite cipher_suite, provider::ProviderPtr provider);
  Cipher(CipherSuiteIdentifier cipher_suite, provider::ProviderPtr provider);

  Cipher(Cipher&& other) noexcept;
  Cipher& operator=(Cipher&& other) noexcept;
  Cipher(const Cipher&) = delete;
  Cipher& operator=(const Cipher&) = delete;

  ///
  /// Cipher properties
  ///
  std::size_t digest_size() const;
  std::size_t key_size() const;
  std::size_t nonce_size() const;
  bool is_ctr_hmac() const;

  ///
  /// HMAC and HKDF
  ///
  bytes hkdf_extract(const bytes& salt, const bytes& ikm) const;
  bytes hkdf_expand(const bytes& secret,
                    const bytes& info,
                    std::size_t size) const;

  ///
  /// AEAD Algorithms
  ///
  output_bytes seal(const bytes& key,
                    const bytes& nonce,
                    output_bytes ct,
                    input_bytes aad,
                    input_bytes pt) const;
  output_bytes open(const bytes& key,
                    const bytes& nonce,
                    output_bytes pt,
                    input_bytes aad,
                    input_bytes ct) const;

protected:
  CipherSuiteIdentifier id;
  provider::ProviderPtr provider;
};

}