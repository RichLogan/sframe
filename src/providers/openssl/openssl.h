#pragma once

#include <array>
#include <cstdint>
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
  ///
  /// Information about algorithms
  ///
  virtual std::set<HashId> supported_hash_algorithms() const override;
  virtual std::set<AEADId> supported_aead_algorithms() const override;
  std::size_t digest_size(HashId algorithm) const override;
  std::size_t key_size(HashId algorithm) const override;
  std::size_t nonce_size(AEADId algorithm) const override;

  ///
  /// HMAC and HKDF
  ///
  bytes hkdf_extract(HashId algorithm,
                     const bytes& salt,
                     const bytes& ikm) const override;
  bytes hkdf_expand(HashId algorithm,
                    const bytes& secret,
                    const bytes& info,
                    std::size_t size) const override;

  ///
  /// AEAD Algorithms
  ///
  output_bytes seal(AEADId aead_algorithm,
                    HashId hash_algorithm,
                    std::size_t tag_size,
                    const bytes& key,
                    const bytes& nonce,
                    output_bytes ct,
                    input_bytes aad,
                    input_bytes pt) const override;
  output_bytes open(AEADId aeadAlgorithm,
                    HashId hash_algorithm,
                    std::size_t tag_size,
                    const bytes& key,
                    const bytes& nonce,
                    output_bytes pt,
                    input_bytes aad,
                    input_bytes ct) const override;

private:
  bytes hmac_for_hkdf(HashAlgorithm cipher,
                      input_bytes key,
                      input_bytes data) const;
  output_bytes seal_ctr(AEADAlgorithm aeadAlgorithm,
                        HashAlgorithm hashAlgorithm,
                        std::size_t tag_size,
                        const bytes& key,
                        const bytes& nonce,
                        output_bytes ct,
                        input_bytes aad,
                        input_bytes pt) const;
  output_bytes open_ctr(AEADAlgorithm aead_algorithm,
                        HashAlgorithm hash_algorithm,
                        std::size_t tag_size,
                        const bytes& key,
                        const bytes& nonce,
                        output_bytes pt,
                        input_bytes aad,
                        input_bytes ct) const;
};

struct HMAC
{
  HMAC(HashAlgorithm algorithm, input_bytes key);
  void write(input_bytes data);
  input_bytes digest();

  scoped_hmac_ctx ctx;
  std::array<std::uint8_t, EVP_MAX_MD_SIZE> md;
};

}
}
}