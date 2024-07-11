#include <sframe/cipher.h>

namespace sframe {

Cipher::Cipher(CipherSuite cipher_suite, provider::ProviderPtr provider)
  : Cipher(static_cast<CipherSuiteIdentifier>(cipher_suite),
           std::move(provider))
{
}

Cipher::Cipher(CipherSuiteIdentifier cipher_suite,
               provider::ProviderPtr provider)
  : id(cipher_suite)
  , provider(std::move(provider))
{
}

Cipher::Cipher(Cipher&& other) noexcept
  : id(other.id)
  , provider(std::move(other.provider))
{
}

Cipher&
Cipher::operator=(Cipher&& other) noexcept
{
  id = other.id;
  provider = std::move(other.provider);
  return *this;
}

std::size_t
Cipher::digest_size() const
{
  return provider->cipher_digest_size(id);
}

std::size_t
Cipher::key_size() const
{
  return provider->cipher_key_size(id);
}

std::size_t
Cipher::nonce_size() const
{
  return provider->cipher_nonce_size(id);
}

bool
Cipher::is_ctr_hmac() const
{
  return id == static_cast<CipherSuiteIdentifier>(
                 CipherSuite::AES_CM_128_HMAC_SHA256_4) ||
         id == static_cast<CipherSuiteIdentifier>(
                 CipherSuite::AES_CM_128_HMAC_SHA256_8);
}

///
/// HMAC and HKDF
///
bytes
Cipher::hkdf_extract(const bytes& salt, const bytes& ikm) const
{
  return provider->hkdf_extract(id, salt, ikm);
}

bytes
Cipher::hkdf_expand(const bytes& secret,
                    const bytes& info,
                    std::size_t size) const
{
  return provider->hkdf_expand(id, secret, info, size);
}

///
/// AEAD Algorithms
///
output_bytes
Cipher::seal(const bytes& key,
             const bytes& nonce,
             output_bytes ct,
             input_bytes aad,
             input_bytes pt) const
{
  return provider->seal(id, key, nonce, ct, aad, pt);
}

output_bytes
Cipher::open(const bytes& key,
             const bytes& nonce,
             output_bytes pt,
             input_bytes aad,
             input_bytes ct) const
{
  return provider->open(id, key, nonce, pt, aad, ct);
}

} // namespace sframe