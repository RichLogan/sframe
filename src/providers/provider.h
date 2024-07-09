#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <gsl/gsl-lite.hpp>
#include <stdexcept>
#include <vector>

namespace sframe {

struct unsupported_ciphersuite_error : std::runtime_error
{
  unsupported_ciphersuite_error()
    : std::runtime_error("Unsupported ciphersuite")
  {
  }
};

struct authentication_error : std::runtime_error
{
  authentication_error()
    : std::runtime_error("AEAD authentication failure")
  {
  }
};

struct buffer_too_small_error : std::runtime_error
{
  using parent = std::runtime_error;
  using parent::parent;
};

struct invalid_parameter_error : std::runtime_error
{
  using parent = std::runtime_error;
  using parent::parent;
};

using bytes = std::vector<std::uint8_t>;
using input_bytes = gsl::span<const std::uint8_t>;
using output_bytes = gsl::span<std::uint8_t>;

namespace provider {

enum class CipherSuite : std::uint16_t
{
  AES_CM_128_HMAC_SHA256_4 = 1,
  AES_CM_128_HMAC_SHA256_8 = 2,
  AES_GCM_128_SHA256 = 3,
  AES_GCM_256_SHA512 = 4,
};

struct Provider
{
  virtual ~Provider() = default;

  ///
  /// Information about algorithms
  ///
  virtual std::size_t cipher_digest_size(CipherSuite suite) const = 0;
  virtual std::size_t cipher_key_size(CipherSuite suite) const = 0;
  virtual std::size_t cipher_nonce_size(CipherSuite suite) const = 0;

  ///
  /// HMAC and HKDF
  ///
  virtual bytes hkdf_extract(CipherSuite suite,
                             const bytes& salt,
                             const bytes& ikm) const = 0;
  virtual bytes hkdf_expand(CipherSuite suite,
                            const bytes& secret,
                            const bytes& info,
                            std::size_t size) const = 0;

  ///
  /// AEAD Algorithms
  ///
  virtual output_bytes seal(CipherSuite suite,
                            const bytes& key,
                            const bytes& nonce,
                            output_bytes ct,
                            input_bytes aad,
                            input_bytes pt) const = 0;
  virtual output_bytes open(CipherSuite suite,
                            const bytes& key,
                            const bytes& nonce,
                            output_bytes pt,
                            input_bytes aad,
                            input_bytes ct) const = 0;
};

typedef std::unique_ptr<Provider> ProviderPtr;

} // namespace provider
} // namespace sframe
