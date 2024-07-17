#include <doctest/doctest.h>
#include "test_suite.h"
#include "openssl.h"
#include <openssl/crypto.h>

using namespace sframe::provider::openssl;

TEST_CASE("FIPS")
{
  const auto* require = std::getenv("REQUIRE_FIPS");
  if (require && FIPS_mode() == 0) {
    REQUIRE(FIPS_mode_set(1) == 1);
  }
}

TYPE_TO_STRING_AS("OpenSSL", OpenSSLProvider);
TEST_CASE_TEMPLATE_INVOKE(test_suite, OpenSSLProvider);