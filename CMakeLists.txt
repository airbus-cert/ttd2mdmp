# Minimum CMake required
cmake_minimum_required(VERSION 3.11)

# Project
project(ttd2mdmp LANGUAGES CXX VERSION 1.0.0)

# Opions
option(BUILD_TESTS "Build test programs" OFF)
option(INSTALL_TTDDLL "Try to find and install ttd dll from Windbg Preview install folder" OFF)

# Config
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

# Add cmake folder for 
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Install ttd dlls if it's requested
# Use when generate installer
if (WindbgPreview_INSTALL_PATH)
	message(STATUS "Find package TTD")
	find_package(TTDReplay)
	INSTALL_TTDREPLAY("${EXECUTABLE_OUTPUT_PATH}")
endif (WindbgPreview_INSTALL_PATH)

add_subdirectory(ttd2mdmp)

# Tests
if(BUILD_TESTS)
    add_subdirectory(tests)
endif(BUILD_TESTS)

# Summary
message(STATUS "Configuration summary")
message(STATUS "Project name                 : ${PROJECT_NAME}")
message(STATUS "Project version              : ${PROJECT_VERSION}")
message(STATUS "Build Tests                  : ${BUILD_TESTS}")
message(STATUS "Install TTD Dlls             : ${WindbgPreview_INSTALL_PATH}")
