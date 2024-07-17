set(TEST_APP_NAME "${LIB_NAME}_test")

# Dependencies
find_package(doctest REQUIRED)
include(doctest)

# Test suite interface.
add_library(${LIB_NAME}_test_suite INTERFACE test_suite.h)
target_link_libraries(${LIB_NAME}_test_suite INTERFACE ${LIB_NAME} doctest::doctest)
install(TARGETS ${LIB_NAME}_test_suite EXPORT ${PROJECT_NAME}-targets)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/test_suite.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

# OpenSSL provider test.
if (BUILD_OPENSSL)
    add_executable(${TEST_APP_NAME}_openssl main.cpp openssl.cpp)
    target_link_libraries(${TEST_APP_NAME}_openssl ${LIB_NAME}_openssl ${LIB_NAME}_test_suite)
    doctest_discover_tests(${TEST_APP_NAME}_openssl)
endif(BUILD_OPENSSL)
