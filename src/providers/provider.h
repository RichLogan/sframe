#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <gsl/gsl-lite.hpp>
#include <set>
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
using CipherSuiteId = std::uint16_t;

namespace provider {

struct Provider
{
  virtual ~Provider() = default;

  ///
  /// Information about algorithms
  ///
  virtual std::set<CipherSuiteId> supported_ciphersuites() const = 0;
  virtual std::size_t cipher_digest_size(
    CipherSuiteId cipher) const = 0;
  virtual std::size_t cipher_key_size(CipherSuiteId cipher) const = 0;
  virtual std::size_t cipher_nonce_size(CipherSuiteId cipher) const = 0;

  ///
  /// HMAC and HKDF
  ///
  virtual bytes hkdf_extract(CipherSuiteId cipher,
                             const bytes& salt,
                             const bytes& ikm) const = 0;
  virtual bytes hkdf_expand(CipherSuiteId cipher,
                            const bytes& secret,
                            const bytes& info,
                            std::size_t size) const = 0;

  ///
  /// AEAD Algorithms
  ///
  virtual output_bytes seal(CipherSuiteId cipher,
                            const bytes& key,
                            const bytes& nonce,
                            output_bytes ct,
                            input_bytes aad,
                            input_bytes pt) const = 0;
  virtual output_bytes open(CipherSuiteId cipher,
                            const bytes& key,
                            const bytes& nonce,
                            output_bytes pt,
                            input_bytes aad,
                            input_bytes ct) const = 0;
};

typedef std::unique_ptr<Provider> ProviderPtr;

} // namespace provider
} // namespace sframe
