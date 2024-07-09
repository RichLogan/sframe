# Provider interface.
add_library(${LIB_NAME}_provider INTERFACE provider.h)
target_include_directories(${LIB_NAME}_provider INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${LIB_NAME}_provider INTERFACE gsl)

# Builtin providers.
if (BUILTIN_PROVIDER)
    add_subdirectory(openssl)
endif(BUILTIN_PROVIDER)