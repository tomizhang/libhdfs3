cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

PROJECT(libhdfs3)

SET(CMAKE_VERBOSE_MAKEFILE ON CACHE STRING "Verbose build." FORCE)
# set(CMAKE_POSITION_INDEPENDENT_CODE ON)

IF(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    MESSAGE(FATAL_ERROR "cannot build the project in the source directory! Out-of-source build is enforced!")
ENDIF()

SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})
SET(DOXYFILE_PATH ${CMAKE_SOURCE_DIR}/docs)

INCLUDE(Platform)
INCLUDE(Functions)
INCLUDE(Options)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

FIND_PACKAGE(Git)
if(Git_FOUND)
  if (NOT DEFINED libhdfs3_GIT_COMMIT_HASH)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} log -1 --format=%h
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            RESULT_VARIABLE libhdfs3_GIT_RESULT
            OUTPUT_VARIABLE libhdfs3_GIT_COMMIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
  execute_process(
          COMMAND ${GIT_EXECUTABLE} describe --tags --abbrev=0
          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
          OUTPUT_VARIABLE libhdfs3_GIT_LAST_TAG
          OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process(
          COMMAND ${GIT_EXECUTABLE} describe --tags --long
          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
          OUTPUT_VARIABLE libhdfs3_GIT_ITERATION
          OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
  message("Git NOT FOUND")
endif()

set(libhdfs3_VERSION_MAJOR 3)
set(libhdfs3_VERSION_MINOR 0)
set(libhdfs3_VERSION_PATCH 0)
set(libhdfs3_DEV_ITERATION 0)

if(libhdfs3_GIT_RESULT EQUAL "0")
  if(libhdfs3_GIT_LAST_TAG)
    string(REGEX REPLACE "v([0-9]+).[0-9]+.[0-9]+" "\\1" libhdfs3_VERSION_MAJOR "${libhdfs3_GIT_LAST_TAG}")
    string(REGEX REPLACE "v[0-9]+.([0-9]+).[0-9]+" "\\1" libhdfs3_VERSION_MINOR "${libhdfs3_GIT_LAST_TAG}")
    string(REGEX REPLACE "v[0-9]+.[0-9]+.([0-9]+)" "\\1" libhdfs3_VERSION_PATCH "${libhdfs3_GIT_LAST_TAG}")
  endif()
  string(REGEX REPLACE ".*-([0-9]+)-.*" "\\1" libhdfs3_DEV_ITERATION "${libhdfs3_GIT_ITERATION}")
  if(libhdfs3_DEV_ITERATION EQUAL 0)
    # on a tag; directly use the version
    set(libhdfs3_VERSION "${libhdfs3_GIT_LAST_TAG}[${libhdfs3_GIT_COMMIT_HASH}]")
  else()
    # not on a tag, increment the patch version by one and add a -devX suffix
    math(EXPR libhdfs3_VERSION_PATCH "${libhdfs3_VERSION_PATCH}+1")
    set(libhdfs3_VERSION "v${libhdfs3_VERSION_MAJOR}.${libhdfs3_VERSION_MINOR}.${libhdfs3_VERSION_PATCH}-dev${libhdfs3_DEV_ITERATION}[${libhdfs3_GIT_COMMIT_HASH}]")
  endif()
else()
  # fallback for when building from tarball
  set(libhdfs3_VERSION "v${libhdfs3_VERSION_MAJOR}.${libhdfs3_VERSION_MINOR}.${libhdfs3_VERSION_PATCH}-dev${libhdfs3_DEV_ITERATION}")
endif()

set(libhdfs3_VERSION_STRING "${libhdfs3_VERSION}")
add_definitions(-Dlibhdfs3_GIT_COMMIT_HASH="${libhdfs3_GIT_COMMIT_HASH}")
add_definitions(-Dlibhdfs3_VERSION="${libhdfs3_VERSION}")
message("libhdfs3_VERSION: ${libhdfs3_VERSION}")

SET(CMAKE_PREFIX_PATH "/usr/local;${CMAKE_PREFIX_PATH}")
FIND_PACKAGE(OpenSSL REQUIRED)
FIND_PACKAGE(KERBEROS REQUIRED)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so" ".dylib") 
FIND_PACKAGE(LibXml2 REQUIRED)
FIND_PACKAGE(Protobuf REQUIRED)
FIND_PACKAGE(GSasl REQUIRED)

message(STATUS "OPENSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
message(STATUS "KERBEROS_LIBRARIES: ${KERBEROS_LIBRARIES}")
message(STATUS "GSASL_LIBRARIES: ${GSASL_LIBRARIES}")
message(STATUS "GSASL_INCLUDE_DIR: ${GSASL_INCLUDE_DIR}")
message(STATUS "LIBXML2_LIBRARIES: ${LIBXML2_LIBRARIES}")
message(STATUS "LIBXML2_INCLUDE_DIR: ${LIBXML2_INCLUDE_DIR}")
message(STATUS "PROTOBUF_LIBRARIES: ${PROTOBUF_LIBRARIES}")
message(STATUS "PROTOBUF_INCLUDE_DIRS: ${PROTOBUF_INCLUDE_DIRS}")
message(STATUS "Protobuf_PROTOC_EXECUTABLE: ${Protobuf_PROTOC_EXECUTABLE}")

ADD_SUBDIRECTORY(mock)
ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(gtest)
ADD_SUBDIRECTORY(gmock)
ADD_SUBDIRECTORY(test)
OPTION(BUILD_HDFS_BENCHMARK "Build hdfs_benchmark" OFF)
IF(BUILD_HDFS_BENCHMARK)
    ADD_SUBDIRECTORY(hdfs_benchmark)
ENDIF(BUILD_HDFS_BENCHMARK)

ADD_CUSTOM_TARGET(doc
	COMMAND doxygen ${CMAKE_BINARY_DIR}/src/doxyfile
	WORKING_DIRECTORY ${DOXYFILE_PATH}
	COMMENT "Generate documents..."
)

ADD_CUSTOM_TARGET(style
	COMMAND astyle --style=attach --indent=spaces=4 --indent-preprocessor --break-blocks --pad-oper --pad-header --unpad-paren --delete-empty-lines --suffix=none --align-pointer=middle --lineend=linux --indent-col1-comments ${libhdfs3_SOURCES}
	COMMAND astyle --style=attach --indent=spaces=4 --indent-preprocessor --break-blocks --pad-oper --pad-header --unpad-paren --delete-empty-lines --suffix=none --align-pointer=middle --lineend=linux --indent-col1-comments ${unit_SOURCES}
	COMMAND astyle --style=attach --indent=spaces=4 --indent-preprocessor --break-blocks --pad-oper --pad-header --unpad-paren --delete-empty-lines --suffix=none --align-pointer=middle --lineend=linux --indent-col1-comments ${function_SOURCES}
	COMMAND astyle --style=attach --indent=spaces=4 --indent-preprocessor --break-blocks --pad-oper --pad-header --unpad-paren --delete-empty-lines --suffix=none --align-pointer=middle --lineend=linux --indent-col1-comments ${secure_SOURCES}
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	COMMENT "format code style..."
)
