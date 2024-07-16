cmake_minimum_required(VERSION 3.5)

project(sframe
  VERSION 0.1
  LANGUAGES CXX
)

option(TESTING    "Build tests" OFF)
option(CLANG_TIDY "Perform linting with clang-tidy" OFF)
option(SANITIZERS "Enable sanitizers" OFF)
option(BUILTIN_PROVIDER "Use the built-in OpenSSL crypto provider" ON)
option(BUILD_OPENSSL "Build the OpenSSL crypto provider" ON)

###
### Global Config
###
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  add_compile_options(-Wall -pedantic -Wextra -Werror -Wmissing-declarations)
elseif(MSVC)
  add_compile_options(/W4 /WX)

  # MSVC helpfully recommends safer equivalents for things like
  # getenv, but they are not portable.
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

if (SANITIZERS AND (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU"))
  set (SANITIZERS "-fsanitize=address -fsanitize=undefined")
  set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS}             ${SANITIZERS}")
  set (CMAKE_CXX_FLAGS            "${CMAKE_CXX_FLAGS}           ${SANITIZERS}")
  set (CMAKE_EXE_LINKER_FLAGS     "${CMAKE_EXE_LINKER_FLAGS}    ${SANITIZERS}")
  set (CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZERS}")
  set (CMAKE_MODULE_LINKER_FLAGS  "${CMAKE_MODULE_LINKER_FLAGS} ${SANITIZERS}")
endif()

if(CLANG_TIDY)
  find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
  if(CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY  ${CLANG_TIDY_EXE})
  else()
    message(WARNING "clang-tidy requested, but not found")
  endif()
endif()

###
### Dependencies
###

# gsl-lite fetched from GitHub
include( ExternalProject )
find_package( Git REQUIRED )
set( GSL_LITE_URL https://github.com/gsl-lite/gsl-lite.git )
set_directory_properties( PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/third_party )

ExternalProject_Add(
    gsl-extern
    GIT_REPOSITORY ${GSL_LITE_URL}
    TIMEOUT 10
    UPDATE_COMMAND ${GIT_EXECUTABLE} pull
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
   )

ExternalProject_Get_Property( gsl-extern SOURCE_DIR )
set( GSL_LITE_INCLUDE_DIR ${SOURCE_DIR}/include CACHE INTERNAL "Include folder for gsl-lite" )

add_library( gsl INTERFACE )
add_dependencies(gsl gsl-extern)
target_include_directories(gsl
  INTERFACE
    $<BUILD_INTERFACE:${GSL_LITE_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)
install(TARGETS gsl EXPORT ${PROJECT_NAME}-targets)

###
### Library Config
###

set(LIB_NAME "${PROJECT_NAME}")
if (BUILTIN_PROVIDER)
  set(BUILD_OPENSSL ON)
endif(BUILTIN_PROVIDER)
add_subdirectory(src/providers)

add_library(${LIB_NAME}
  src/header.h
  src/header.cpp
  include/sframe/sframe.h
  src/sframe.cpp
  include/sframe/cipher.h
  src/cipher.cpp)
add_dependencies(${LIB_NAME} gsl)
target_link_libraries(${LIB_NAME}
  PRIVATE
    gsl
  PUBLIC
    "${PROJECT_NAME}_provider")
if(BUILTIN_PROVIDER)
  target_link_libraries(${LIB_NAME} PRIVATE "${PROJECT_NAME}_openssl")
  target_compile_definitions(${LIB_NAME} PUBLIC -DBUILTIN_PROVIDER)
endif(BUILTIN_PROVIDER)
target_include_directories(${LIB_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
)
install(TARGETS ${LIB_NAME} EXPORT ${PROJECT_NAME}-targets)

###
### Tests
###
if(TESTING)
  enable_testing()
  add_subdirectory(test)
endif()

###
### Installation
###
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
export(
  EXPORT
    ${PROJECT_NAME}-targets
  NAMESPACE
    ${PROJECT_NAME}::
  FILE
    ${PROJECT_NAME}Targets.cmake)
export(
  PACKAGE
    ${PROJECT_NAME}
)
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
  INSTALL_DESTINATION
    ${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME})
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  VERSION
    ${PROJECT_VERSION}
  COMPATIBILITY
    SameMajorVersion)
install(
  EXPORT
    ${PROJECT_NAME}-targets
  NAMESPACE
    ${PROJECT_NAME}::
  FILE
    ${PROJECT_NAME}Targets.cmake
  DESTINATION
    ${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME})
install(
  DIRECTORY
    include/
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR})
install(
  DIRECTORY
    ${GSL_LITE_INCLUDE_DIR}/
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR})
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  DESTINATION
    ${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME})
install(
  FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
  DESTINATION
    ${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}
  RENAME
    copyright)
