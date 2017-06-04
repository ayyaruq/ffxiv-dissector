project(ffxiv-wireshark-dissector C)

cmake_minimum_required(VERSION 3.7)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
IF (WIN32)
  set(CMAKE_INSTALL_LIBDIR $ENV{APPDATA}/Wireshark/plugins)
ELSE()
  set(CMAKE_INSTALL_LIBDIR ~/.wireshark)
ENDIF()

include(UseMakeDissectorReg)
include(CMakeForceCompiler)

set(GLIB2_MIN_VERSION 2.4.0)

IF(EXTRA_LIB_DIRS)
  LINK_DIRECTORIES(${EXTRA_LIB_DIRS})
ENDIF()

IF(NOT DEFINED ENV{GLIB2_INCLUDE_DIRS})
  find_package(GLIB2)
ELSE()
  SET(GLIB2_INCLUDE_DIRS $ENV{GLIB2_INCLUDE_DIRS})
ENDIF()
include_directories (${GLIB2_INCLUDE_DIRS})

IF(NOT DEFINED GCRYPT_INCLUDE_DIR)
  find_package(Gcrypt)
ELSE()
  set(GLIB2_INCLUDE_DIRS $ENV{GCRYPT_INCLUDE_DIR})
ENDIF()
include_directories (${GCRYPT_INCLUDE_DIR})

IF(NOT DEFINED WIRESHARK_INCLUDE_DIRS)
  find_package(Wireshark)
ELSE()
  set(GLIB2_INCLUDE_DIRS $ENV{WIRESHARK_INCLUDE_DIRS})
ENDIF()
include_directories (${WIRESHARK_INCLUDE_DIRS})

set(LINK_MODE_LIB SHARED)
set(LINK_MODE_MODULE MODULE)

set(DISSECTOR_SRC
  src/packet-ffxiv.c
)

set(DISSECTOR_UTILITY_SRC)

set(PLUGIN_FILES
  plugin.c
  ${DISSECTOR_SRC}
  ${DISSECTOR_UTILITY_SRC}
)

set(CLEAN_FILES
  ${PLUGIN_FILES}
)

set_source_files_properties(
  ${CLEAN_FILES}
  PROPERTIES
  COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_dissector_files(plugin.c
  plugin
  ${DISSECTOR_SRC}
  ${DISSECTOR_UTILITY_SRC}
)

add_library(ffxiv ${LINK_MODE_MODULE}
  ${PLUGIN_FILES}
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

IF (WIN32)
  target_link_libraries(ffxiv wireshark glib-2.0)
ELSE()
  target_link_libraries(ffxiv wireshark gcrypt glib-2.0)
ENDIF()


install(TARGETS ffxiv
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/plugins NAMELINK_SKIP
)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "src/*.h")

#CHECKAPI(
#    NAME
#      ff14
#    SWITCHES
#      -g abort -g termoutput -build
#    SOURCES
#      ${DISSECTOR_SRC}
#      ${DISSECTOR_HEADERS}
#)

#add_custom_command(TARGET ff14
# POST_BUILD
# COMMAND ${CMAKE_STRIP} --strip-debug --strip-unneeded libffxiv.so
#)
