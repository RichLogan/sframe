find_package(OpenSSL REQUIRED)
add_library(${LIB_NAME}_openssl openssl.cpp openssl.h)
target_include_directories(${LIB_NAME}_openssl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${LIB_NAME}_openssl PUBLIC OpenSSL::Crypto ${LIB_NAME}_provider)