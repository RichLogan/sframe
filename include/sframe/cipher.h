#pragma once

#include <cstdint>
#include <sframe/provider.h>

namespace sframe {

/// Represents an sframe cipher suite and its constituent algorithms as
/// understood by a provider.
struct CipherSuiteId
{
  std::uint16_t id;
  AEADId aead_id;
  HashId hash_id;
  std::size_t tag_size;
};

// Built in cipher suite identifiers.
enum class CipherSuite : std::uint16_t
{
  AES_CM_128_HMAC_SHA256_4 = 1,
  AES_CM_128_HMAC_SHA256_8 = 2,
  AES_GCM_128_SHA256 = 3,
  AES_GCM_256_SHA512 = 4,
};

class CipherSuiteImpl
{
public:
  CipherSuiteImpl(CipherSuite cipher_suite, provider::ProviderPtr provider);
  CipherSuiteImpl(CipherSuiteId cipher_suite, provider::ProviderPtr provider);

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
  CipherSuiteId id;
  provider::ProviderPtr provider;
};

}