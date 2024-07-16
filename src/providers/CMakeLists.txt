# Provider interface.
add_library(${LIB_NAME}_provider provider.cpp)
target_include_directories(${LIB_NAME}_provider
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)
target_link_libraries(${LIB_NAME}_provider PUBLIC gsl)
install(TARGETS ${LIB_NAME}_provider EXPORT ${PROJECT_NAME}-targets)

# Builtin providers.
if (BUILD_OPENSSL)
    add_subdirectory(openssl)
endif(BUILD_OPENSSL)