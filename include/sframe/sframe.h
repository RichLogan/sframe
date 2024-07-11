#pragma once

#include <iosfwd>
#include <map>
#include <memory>
#include <vector>
#include <provider.h>
#include <sframe/cipher.h>

#include <gsl/gsl-lite.hpp>

namespace sframe {

constexpr size_t max_overhead = 17 + 16;

std::ostream&
operator<<(std::ostream& str, const input_bytes data);

using KeyID = uint64_t;
using Counter = uint64_t;

class SFrame
{
protected:
  Cipher suite;

  #if defined(BUILTIN_PROVIDER)
  // [[deprecated]]
  SFrame(CipherSuite suite_in);
  #endif
  SFrame(Cipher suite);
  SFrame(SFrame&& other) noexcept;
  SFrame& operator=(SFrame&& other) noexcept;
  SFrame(const SFrame&) = delete;
  SFrame& operator=(const SFrame&) = delete;

  virtual ~SFrame();

  struct KeyState
  {
    static KeyState from_base_key(const bytes& base_key, const Cipher& cipher);

    bytes key;
    bytes salt;
    Counter counter;
  };

  output_bytes _protect(KeyID key_id,
                        output_bytes ciphertext,
                        input_bytes plaintext);
  output_bytes _unprotect(output_bytes ciphertext, input_bytes plaintext);

  virtual KeyState& get_state(KeyID key_id) = 0;
};

class Context : public SFrame
{
public:
#if defined(BUILTIN_PROVIDER)
  // [[deprecated]]
  Context(CipherSuite suite);
#endif
  Context(Cipher cipher);

  void add_key(KeyID kid, const bytes& key);

  output_bytes protect(KeyID key_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes unprotect(output_bytes plaintext, input_bytes ciphertext);

private:
  std::map<KeyID, KeyState> state;

  KeyState& get_state(KeyID key_id) override;
};

class MLSContext : public SFrame
{
public:
  using EpochID = uint64_t;
  using SenderID = uint64_t;
  using ContextID = uint64_t;

#if defined(BUILTIN_PROVIDER)
  // [[deprecated]]
  MLSContext(CipherSuite suite_in, size_t epoch_bits_in);
#endif
  MLSContext(Cipher cipher, size_t epoch_bits_in);

  void add_epoch(EpochID epoch_id, const bytes& sframe_epoch_secret);
  void add_epoch(EpochID epoch_id,
                 const bytes& sframe_epoch_secret,
                 size_t sender_bits);
  void purge_before(EpochID keeper);

  output_bytes protect(EpochID epoch_id,
                       SenderID sender_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes protect(EpochID epoch_id,
                       SenderID sender_id,
                       ContextID context_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);

  output_bytes unprotect(output_bytes plaintext, input_bytes ciphertext);

private:
  const size_t epoch_bits;
  const size_t epoch_mask;

  struct EpochKeys
  {
    const EpochID full_epoch;
    const bytes sframe_epoch_secret;
    const size_t sender_bits;
    std::map<SenderID, KeyState> sender_keys;

    EpochKeys(EpochID full_epoch_in,
              bytes sframe_epoch_secret_in,
              size_t sender_bits_in);
    KeyState& get(SenderID sender_id, const Cipher& cipher);
  };

  std::vector<std::unique_ptr<EpochKeys>> epoch_cache;
  KeyState& get_state(KeyID key_id) override;
};

} // namespace sframe
