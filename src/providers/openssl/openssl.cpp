#include "openssl.h"
#include <openssl/err.h>
#include <openssl/evp.h>

namespace sframe {
namespace provider {
namespace openssl {

using scoped_evp_ctx =
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

openssl_error::openssl_error()
  : std::runtime_error(ERR_error_string(ERR_get_error(), nullptr))
{
}

static const EVP_MD*
openssl_digest_type(HashAlgorithm algorithm)
{
  switch (algorithm) {
    case HashAlgorithm::SHA256:
      return EVP_sha256();
    case HashAlgorithm::SHA512:
      return EVP_sha512();
    default:
      throw unsupported_ciphersuite_error();
  }
}

static const EVP_CIPHER*
openssl_cipher(AEADAlgorithm algorithm)
{
  switch (algorithm) {
    case AEADAlgorithm::AES_CM_128:
      return EVP_aes_128_ctr();
    case AEADAlgorithm::AES_GCM_128:
      return EVP_aes_128_gcm();
    case AEADAlgorithm::AES_GCM_256:
      return EVP_aes_256_gcm();
    default:
      throw unsupported_ciphersuite_error();
  }
}

static std::size_t
openssl_digest_size(HashAlgorithm algorithm)
{
  return EVP_MD_size(openssl_digest_type(algorithm));
}

///
/// Information about algorithms
///

std::set<HashId>
OpenSSLProvider::supported_hash_algorithms() const
{
  return { static_cast<HashId>(HashAlgorithm::SHA256),
           static_cast<HashId>(HashAlgorithm::SHA512) };
}

std::set<AEADId>
OpenSSLProvider::supported_aead_algorithms() const
{
  return { static_cast<AEADId>(AEADAlgorithm::AES_CM_128),
           static_cast<AEADId>(AEADAlgorithm::AES_GCM_128),
           static_cast<AEADId>(AEADAlgorithm::AES_GCM_256) };
}

std::size_t
OpenSSLProvider::digest_size(HashId algorithm) const
{
  return openssl_digest_size(static_cast<HashAlgorithm>(algorithm));
}

static std::size_t
openssl_key_size(AEADAlgorithm algorithm)
{
  switch (algorithm) {
    case AEADAlgorithm::AES_CM_128:
    case AEADAlgorithm::AES_GCM_128:
      return 16;

    case AEADAlgorithm::AES_GCM_256:
      return 32;

    default:
      throw unsupported_ciphersuite_error();
  }
}

std::size_t
OpenSSLProvider::key_size(AEADId algorithm) const
{
  return openssl_key_size(static_cast<AEADAlgorithm>(algorithm));
}

std::size_t
OpenSSLProvider::nonce_size(AEADId algorithm) const
{
  switch (algorithm) {
    case static_cast<AEADId>(AEADAlgorithm::AES_CM_128):
    case static_cast<AEADId>(AEADAlgorithm::AES_GCM_128):
    case static_cast<AEADId>(AEADAlgorithm::AES_GCM_256):
      return 12;

    default:
      throw unsupported_ciphersuite_error();
  }
}

///
/// HMAC and HKDF
///

HMAC::HMAC(HashAlgorithm algorithm, input_bytes key)
  : ctx(HMAC_CTX_new(), HMAC_CTX_free)
{
  auto type = openssl_digest_type(algorithm);
  auto key_size = static_cast<int>(key.size());
  if (1 != HMAC_Init_ex(ctx.get(), key.data(), key_size, type, nullptr)) {
    throw openssl_error();
  }
}

void
HMAC::write(input_bytes data)
{
  if (1 != HMAC_Update(ctx.get(), data.data(), data.size())) {
    throw openssl_error();
  }
}

input_bytes
HMAC::digest()
{
  unsigned int size = 0;
  if (1 != HMAC_Final(ctx.get(), md.data(), &size)) {
    throw openssl_error();
  }

  return input_bytes(md.data(), size);
}

bytes
OpenSSLProvider::hmac_for_hkdf(HashAlgorithm algorithm,
                               input_bytes key,
                               input_bytes data) const
{
  const auto type = openssl_digest_type(algorithm);
  auto ctx = scoped_hmac_ctx(HMAC_CTX_new(), HMAC_CTX_free);

  // Some FIPS-enabled libraries are overly conservative in their interpretation
  // of NIST SP 800-131A, which requires HMAC keys to be at least 112 bits long.
  // That document does not impose that requirement on HKDF, so we disable FIPS
  // enforcement for purposes of HKDF.
  //
  // https://doi.org/10.6028/NIST.SP.800-131Ar2
  static const auto fips_min_hmac_key_len = 14;
  auto key_size = static_cast<int>(key.size());
  if (FIPS_mode() != 0 && key_size < fips_min_hmac_key_len) {
    HMAC_CTX_set_flags(ctx.get(), EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
  }

  // Guard against sending nullptr to HMAC_Init_ex
  const auto* key_data = key.data();
  const auto non_null_zero_length_key = uint8_t(0);
  if (key_data == nullptr) {
    key_data = &non_null_zero_length_key;
  }

  if (1 != HMAC_Init_ex(ctx.get(), key_data, key_size, type, nullptr)) {
    throw openssl_error();
  }

  if (1 != HMAC_Update(ctx.get(), data.data(), data.size())) {
    throw openssl_error();
  }

  auto md = bytes(openssl_digest_size(algorithm));
  unsigned int size = 0;
  if (1 != HMAC_Final(ctx.get(), md.data(), &size)) {
    throw openssl_error();
  }

  return md;
}

bytes
OpenSSLProvider::hkdf_extract(HashId algorithm,
                              const bytes& salt,
                              const bytes& ikm) const
{
  return hmac_for_hkdf(static_cast<HashAlgorithm>(algorithm), salt, ikm);
}

bytes
OpenSSLProvider::hkdf_expand(HashId algorithm,
                             const bytes& secret,
                             const bytes& info,
                             std::size_t size) const
{
  // Ensure that we need only one hash invocation
  if (size > digest_size(algorithm)) {
    throw invalid_parameter_error("Size too big for hkdf_expand");
  }

  auto label = info;
  label.push_back(0x01);
  auto mac =
    hmac_for_hkdf(static_cast<HashAlgorithm>(algorithm), secret, label);
  mac.resize(size);
  return mac;
}

static void
ctr_crypt(AEADAlgorithm algorithm,
          input_bytes key,
          input_bytes nonce,
          output_bytes out,
          input_bytes in)
{
  if (out.size() != in.size()) {
    throw buffer_too_small_error("CTR size mismatch");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  static auto padded_nonce =
    std::array<uint8_t, 16>{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  std::copy(nonce.begin(), nonce.end(), padded_nonce.begin());

  auto cipher = openssl_cipher(algorithm);
  if (1 !=
      EVP_EncryptInit(ctx.get(), cipher, key.data(), padded_nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  auto in_size_int = static_cast<int>(in.size());
  if (1 != EVP_EncryptUpdate(
             ctx.get(), out.data(), &outlen, in.data(), in_size_int)) {
    throw openssl_error();
  }

  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
  }
}

output_bytes
OpenSSLProvider::seal_ctr(AEADAlgorithm aead_algorithm,
                          HashAlgorithm hash_algorithm,
                          std::size_t tag_size,
                          const bytes& key,
                          const bytes& nonce,
                          output_bytes ct,
                          input_bytes aad,
                          input_bytes pt) const
{
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  // Split the key into enc and auth subkeys
  auto key_span = input_bytes(key);
  auto enc_key_size = openssl_key_size(aead_algorithm);
  auto enc_key = key_span.subspan(0, enc_key_size);
  auto auth_key = key_span.subspan(enc_key_size);

  // Encrypt with AES-CM
  auto inner_ct = ct.subspan(0, pt.size());
  ctr_crypt(aead_algorithm, enc_key, nonce, inner_ct, pt);

  // Authenticate with truncated HMAC
  auto hmac = HMAC(hash_algorithm, auth_key);
  hmac.write(aad);
  hmac.write(inner_ct);
  auto mac = hmac.digest();
  auto tag = ct.subspan(pt.size(), tag_size);
  std::copy(mac.begin(), mac.begin() + tag_size, tag.begin());

  return ct.subspan(0, pt.size() + tag_size);
}

static output_bytes
seal_aead(AEADAlgorithm algorithm,
          std::size_t tag_size,
          const bytes& key,
          const bytes& nonce,
          output_bytes ct,
          input_bytes aad,
          input_bytes pt)
{
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(algorithm);
  if (1 != EVP_EncryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 != EVP_EncryptUpdate(
               ctx.get(), nullptr, &outlen, aad.data(), aad_size_int)) {
      throw openssl_error();
    }
  }

  auto pt_size_int = static_cast<int>(pt.size());
  if (1 != EVP_EncryptUpdate(
             ctx.get(), ct.data(), &outlen, pt.data(), pt_size_int)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size_downcast, tag_ptr)) {
    throw openssl_error();
  }

  return ct.subspan(0, pt.size() + tag_size);
}

output_bytes
OpenSSLProvider::seal(AEADId aead_algorithm,
                      HashId hash_algorithm,
                      std::size_t tag_size,
                      const bytes& key,
                      const bytes& nonce,
                      output_bytes ct,
                      input_bytes aad,
                      input_bytes pt) const
{
  const auto typed_aead_algorithm = static_cast<AEADAlgorithm>(aead_algorithm);
  const auto typed_hash_algorithm = static_cast<HashAlgorithm>(hash_algorithm);
  switch (typed_aead_algorithm) {
    case AEADAlgorithm::AES_CM_128:
      return seal_ctr(typed_aead_algorithm,
                      typed_hash_algorithm,
                      tag_size,
                      key,
                      nonce,
                      ct,
                      aad,
                      pt);
    case AEADAlgorithm::AES_GCM_128:
    case AEADAlgorithm::AES_GCM_256:
      return seal_aead(typed_aead_algorithm, tag_size, key, nonce, ct, aad, pt);
    default:
      throw unsupported_ciphersuite_error();
  }
}

output_bytes
OpenSSLProvider::open_ctr(AEADAlgorithm aead_algorithm,
                          HashAlgorithm hash_algorithm,
                          std::size_t tag_size,
                          const bytes& key,
                          const bytes& nonce,
                          output_bytes pt,
                          input_bytes aad,
                          input_bytes ct) const
{
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  auto inner_ct = ct.subspan(0, inner_ct_size);
  auto tag = ct.subspan(inner_ct_size, tag_size);

  // Split the key into enc and auth subkeys
  auto key_span = input_bytes(key);
  auto enc_key_size = openssl_key_size(aead_algorithm);
  auto enc_key = key_span.subspan(0, enc_key_size);
  auto auth_key = key_span.subspan(enc_key_size);

  // Authenticate with truncated HMAC
  auto hmac = HMAC(hash_algorithm, auth_key);
  hmac.write(aad);
  hmac.write(inner_ct);
  auto mac = hmac.digest();
  if (CRYPTO_memcmp(mac.data(), tag.data(), tag.size()) != 0) {
    throw authentication_error();
  }

  // Decrypt with AES-CM
  ctr_crypt(aead_algorithm, enc_key, nonce, pt, ct.subspan(0, inner_ct_size));

  return pt.subspan(0, inner_ct_size);
}

static output_bytes
open_aead(AEADAlgorithm algorithm,
          std::size_t tag_size,
          const bytes& key,
          const bytes& nonce,
          output_bytes pt,
          input_bytes aad,
          input_bytes ct)
{
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  if (pt.size() < inner_ct_size) {
    throw buffer_too_small_error("Plaintext buffer too small");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(algorithm);
  if (1 != EVP_DecryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  auto tag = ct.subspan(inner_ct_size, tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size_downcast, tag_ptr)) {
    throw openssl_error();
  }

  int out_size;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, aad.data(), aad_size_int)) {
      throw openssl_error();
    }
  }

  auto inner_ct_size_int = static_cast<int>(inner_ct_size);
  if (1 != EVP_DecryptUpdate(
             ctx.get(), pt.data(), &out_size, ct.data(), inner_ct_size_int)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
    throw authentication_error();
  }

  return pt.subspan(0, inner_ct_size);
}

output_bytes
OpenSSLProvider::open(AEADId aead_algorithm,
                      HashId hash_algorithm,
                      std::size_t tag_size,
                      const bytes& key,
                      const bytes& nonce,
                      output_bytes pt,
                      input_bytes aad,
                      input_bytes ct) const
{
  const auto typed_aead_algorithm = static_cast<AEADAlgorithm>(aead_algorithm);
  const auto typed_hash_algorithm = static_cast<HashAlgorithm>(hash_algorithm);
  switch (typed_aead_algorithm) {
    case AEADAlgorithm::AES_CM_128:
      return open_ctr(typed_aead_algorithm,
                      typed_hash_algorithm,
                      tag_size,
                      key,
                      nonce,
                      pt,
                      aad,
                      ct);
    case AEADAlgorithm::AES_GCM_128:
    case AEADAlgorithm::AES_GCM_256:
      return open_aead(typed_aead_algorithm, tag_size, key, nonce, pt, aad, ct);
  }
  throw unsupported_ciphersuite_error();
}

}
}
}