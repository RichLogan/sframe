#include <sframe/cipher.h>

namespace sframe {

// Built in cipher suite internals.
const CipherSuiteId AES_CM_128_HMAC_SHA256_4 = CipherSuiteId{
  static_cast<std::uint16_t>(CipherSuite::AES_CM_128_HMAC_SHA256_4),
  static_cast<EncryptionId>(provider::EncryptionAlgorithm::AES_CM_128),
  static_cast<HashId>(provider::HashAlgorithm::SHA256),
  4
};
const CipherSuiteId AES_CM_128_HMAC_SHA256_8 = CipherSuiteId{
  static_cast<std::uint16_t>(CipherSuite::AES_CM_128_HMAC_SHA256_8),
  static_cast<EncryptionId>(provider::EncryptionAlgorithm::AES_CM_128),
  static_cast<HashId>(provider::HashAlgorithm::SHA256),
  8
};
const CipherSuiteId AES_GCM_128_SHA256 =
  CipherSuiteId{ static_cast<std::uint16_t>(CipherSuite::AES_GCM_128_SHA256),
                 static_cast<EncryptionId>(provider::EncryptionAlgorithm::AES_GCM_128),
                 static_cast<HashId>(provider::HashAlgorithm::SHA256),
                 16 };
const CipherSuiteId AES_GCM_256_SHA512 =
  CipherSuiteId{ static_cast<std::uint16_t>(CipherSuite::AES_GCM_256_SHA512),
                 static_cast<EncryptionId>(provider::EncryptionAlgorithm::AES_GCM_256),
                 static_cast<HashId>(provider::HashAlgorithm::SHA512),
                 16 };

CipherSuiteImpl::CipherSuiteImpl(CipherSuite cipher_suite,
                                 provider::ProviderPtr provider)
{
  // Resolve built in cipher suites to their internal representation.
  switch (cipher_suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
      id = AES_CM_128_HMAC_SHA256_4;
      break;
    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
      id = AES_CM_128_HMAC_SHA256_8;
      break;
    case CipherSuite::AES_GCM_128_SHA256:
      id = AES_GCM_128_SHA256;
      break;
    case CipherSuite::AES_GCM_256_SHA512:
      id = AES_GCM_256_SHA512;
      break;
    default:
      throw unsupported_ciphersuite_error();
  }
  this->provider = std::move(provider);
}

CipherSuiteImpl::CipherSuiteImpl(CipherSuiteId cipher_suite,
                                 provider::ProviderPtr provider)
  : id(cipher_suite)
  , provider(std::move(provider))
{
}

std::size_t
CipherSuiteImpl::digest_size() const
{
  return provider->digest_size(id.hash_id);
}

std::size_t
CipherSuiteImpl::key_size() const
{
  return provider->key_size(id.encryption_id);
}

std::size_t
CipherSuiteImpl::nonce_size() const
{
  return provider->nonce_size(id.encryption_id);
}

bool
CipherSuiteImpl::is_ctr_hmac() const
{
  return id.encryption_id == static_cast<EncryptionId>(provider::EncryptionAlgorithm::AES_CM_128);
}

///
/// HMAC and HKDF
///
bytes
CipherSuiteImpl::hkdf_extract(const bytes& salt, const bytes& ikm) const
{
  return provider->hkdf_extract(id.hash_id, salt, ikm);
}

bytes
CipherSuiteImpl::hkdf_expand(const bytes& secret,
                             const bytes& info,
                             std::size_t size) const
{
  return provider->hkdf_expand(id.hash_id, secret, info, size);
}

///
/// Crypt Algorithms
///
output_bytes
CipherSuiteImpl::seal(const bytes& key,
                      const bytes& nonce,
                      output_bytes ct,
                      input_bytes aad,
                      input_bytes pt) const
{
  return provider->seal(
    id.encryption_id, id.hash_id, id.tag_size, key, nonce, ct, aad, pt);
}

output_bytes
CipherSuiteImpl::open(const bytes& key,
                      const bytes& nonce,
                      output_bytes pt,
                      input_bytes aad,
                      input_bytes ct) const
{
  return provider->open(
    id.encryption_id, id.hash_id, id.tag_size, key, nonce, pt, aad, ct);
}

} // namespace sframe