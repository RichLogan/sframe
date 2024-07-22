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
    : std::runtime_error("Authentication failure")
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
using HashId = std::uint16_t;
using EncryptionId = std::uint16_t;

namespace provider {

// Common hash functions.
enum class HashAlgorithm : HashId
{
  SHA256 = 1,
  SHA512 = 2,
};

// Common Encryption algorithms.
enum class EncryptionAlgorithm : EncryptionId
{
  AES_CM_128 = 1,
  AES_GCM_128 = 2,
  AES_GCM_256 = 3,
};

// Note to implementors: Although there is scope to use support arbitrary
// algorithms, a provider MUST honour the identifier mappings defined in
// HashAlgorithm and EncryptionAlgorithm.
struct Provider
{
  virtual ~Provider() = default;

  ///
  /// Information about algorithms
  ///
  virtual std::set<HashId> supported_hash_algorithms() const = 0;
  virtual std::set<EncryptionId> supported_encryption_algorithms() const = 0;
  virtual std::size_t digest_size(HashId algorithm) const = 0;
  virtual std::size_t key_size(EncryptionId algorithm) const = 0;
  virtual std::size_t nonce_size(EncryptionId algorithm) const = 0;

  ///
  /// HMAC and HKDF
  ///
  virtual bytes hkdf_extract(HashId algorithm,
                             const bytes& salt,
                             const bytes& ikm) const;

  virtual bytes hkdf_expand(HashId algorithm,
                            const bytes& secret,
                            const bytes& info,
                            std::size_t size) const;

  ///
  /// Crypt Algorithms
  ///
  virtual output_bytes seal(EncryptionId encryption_algorithm,
                            HashId hash_algorithm,
                            std::size_t tag_size,
                            const bytes& key,
                            const bytes& nonce,
                            output_bytes ct,
                            input_bytes aad,
                            input_bytes pt) const = 0;
  virtual output_bytes open(EncryptionId encryption_algorithm,
                            HashId hash_algorithm,
                            std::size_t tag_size,
                            const bytes& key,
                            const bytes& nonce,
                            output_bytes pt,
                            input_bytes aad,
                            input_bytes ct) const = 0;

protected:
  struct HMAC
  {
    virtual ~HMAC() = default;
    virtual void write(input_bytes data) = 0;
    virtual bytes digest() = 0;
  };
  typedef std::unique_ptr<HMAC> HMACPtr;

  virtual bytes hmac_for_hkdf(HashId algorithm,
                              input_bytes key,
                              input_bytes data) const;
  virtual HMACPtr create_hmac(HashId algorithm, input_bytes key) const = 0;
};

typedef std::shared_ptr<Provider> ProviderPtr;

} // namespace provider
} // namespace sframe
