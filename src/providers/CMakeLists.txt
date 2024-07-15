# Provider interface.
add_library(${LIB_NAME}_provider provider.h provider.cpp)
target_include_directories(${LIB_NAME}_provider PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${LIB_NAME}_provider PUBLIC gsl)

# Builtin providers.
if (BUILTIN_PROVIDER)
    add_subdirectory(openssl)
endif(BUILTIN_PROVIDER)