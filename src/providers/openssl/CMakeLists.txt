find_package(OpenSSL REQUIRED)
add_library(${LIB_NAME}_openssl openssl.cpp openssl.h)
target_include_directories(${LIB_NAME}_openssl
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
  PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(${LIB_NAME}_openssl PUBLIC OpenSSL::Crypto ${LIB_NAME}_provider)
install(TARGETS ${LIB_NAME}_openssl EXPORT ${PROJECT_NAME}-targets)