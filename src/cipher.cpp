#include <sframe/cipher.h>

namespace sframe {

CipherSuiteImpl::CipherSuiteImpl(CipherSuite cipher_suite, provider::ProviderPtr provider)
  : CipherSuiteImpl(static_cast<CipherSuiteId>(cipher_suite),
           std::move(provider))
{
}

CipherSuiteImpl::CipherSuiteImpl(CipherSuiteId cipher_suite,
               provider::ProviderPtr provider)
  : id(cipher_suite)
  , provider(std::move(provider))
{
}

CipherSuiteImpl::CipherSuiteImpl(CipherSuiteImpl&& other) noexcept
  : id(other.id)
  , provider(std::move(other.provider))
{
}

CipherSuiteImpl&
CipherSuiteImpl::operator=(CipherSuiteImpl&& other) noexcept
{
  id = other.id;
  provider = std::move(other.provider);
  return *this;
}

std::size_t
CipherSuiteImpl::digest_size() const
{
  return provider->cipher_digest_size(id);
}

std::size_t
CipherSuiteImpl::key_size() const
{
  return provider->cipher_key_size(id);
}

std::size_t
CipherSuiteImpl::nonce_size() const
{
  return provider->cipher_nonce_size(id);
}

bool
CipherSuiteImpl::is_ctr_hmac() const
{
  return id == static_cast<CipherSuiteId>(
                 CipherSuite::AES_CM_128_HMAC_SHA256_4) ||
         id == static_cast<CipherSuiteId>(
                 CipherSuite::AES_CM_128_HMAC_SHA256_8);
}

///
/// HMAC and HKDF
///
bytes
CipherSuiteImpl::hkdf_extract(const bytes& salt, const bytes& ikm) const
{
  return provider->hkdf_extract(id, salt, ikm);
}

bytes
CipherSuiteImpl::hkdf_expand(const bytes& secret,
                    const bytes& info,
                    std::size_t size) const
{
  return provider->hkdf_expand(id, secret, info, size);
}

///
/// AEAD Algorithms
///
output_bytes
CipherSuiteImpl::seal(const bytes& key,
             const bytes& nonce,
             output_bytes ct,
             input_bytes aad,
             input_bytes pt) const
{
  return provider->seal(id, key, nonce, ct, aad, pt);
}

output_bytes
CipherSuiteImpl::open(const bytes& key,
             const bytes& nonce,
             output_bytes pt,
             input_bytes aad,
             input_bytes ct) const
{
  return provider->open(id, key, nonce, pt, aad, ct);
}

} // namespace sframe