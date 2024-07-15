#include <provider.h>

namespace sframe {
namespace provider {

bytes
Provider::hkdf_extract(HashId algorithm,
                       const bytes& salt,
                       const bytes& ikm) const
{
  return hmac_for_hkdf(algorithm, salt, ikm);
}

bytes
Provider::hkdf_expand(HashId algorithm,
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
  auto mac = hmac_for_hkdf(algorithm, secret, label);
  mac.resize(size);
  return mac;
}

bytes
Provider::hmac_for_hkdf(HashId algorithm,
                        input_bytes key,
                        input_bytes data) const
{
  auto hmac = create_hmac(algorithm, key);
  hmac->write(data);
  return hmac->digest();
}

} // namespace provider
} // namespace sframe