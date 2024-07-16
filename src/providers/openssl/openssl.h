#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <openssl/hmac.h>
#include <sframe/provider.h>

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

protected:
  struct OpenSSLHMAC : HMAC
  {
    OpenSSLHMAC(HashAlgorithm algorithm, input_bytes key);
    void check_fips(input_bytes key);
    void write(input_bytes data) override;
    bytes digest() override;

    scoped_hmac_ctx ctx;
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> md;
  };

  Provider::HMACPtr create_hmac(HashId algorithm,
                                input_bytes key) const override;
  Provider::HMACPtr create_hmac(HashAlgorithm algorithm, input_bytes key) const;
  bytes hmac_for_hkdf(HashId cipher,
                      input_bytes key,
                      input_bytes data) const override;
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
}
}
}