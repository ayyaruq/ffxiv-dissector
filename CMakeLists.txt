project(ffxiv-wireshark-dissector C)

cmake_minimum_required(VERSION 3.7)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Wireshark)

if(WIRESHARK_FOUND)

  message(STATUS "Wireshark libraries found, performing a standalone plugin build.")

  if(NOT CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR ~/.wireshark/plugins)
  endif(NOT CMAKE_INSTALL_LIBDIR)

  message(STATUS "Plugin will be installed in ${CMAKE_INSTALL_LIBDIR}")

  include(UseMakeDissectorReg)
  include(CMakeForceCompiler)

  set(GLIB2_MIN_VERSION 2.4.0)

  if(NOT GLIB2_INCLUDE_DIRS)
    find_package(GLIB2)
  endif(NOT GLIB2_INCLUDE_DIRS)

  include_directories(${GLIB2_INCLUDE_DIRS})

  if(NOT GCRYPT_INCLUDE_DIR)
    find_package(Gcrypt)
  endif(NOT GCRYPT_INCLUDE_DIR)

  include_directories(${GCRYPT_INCLUDE_DIR})

  include_directories(${WIRESHARK_INCLUDE_DIRS})

  set(LINK_MODE_LIB SHARED)
  set(LINK_MODE_MODULE MODULE)

else(WIRESHARK_FOUND)

endif(WIRESHARK_FOUND)

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

if(WERROR)
  set_source_files_properties(${CLEAN_FILES}
    PROPERTIES
    COMPILE_FLAGS -Werror "${WERROR_COMMON_FLAGS}"
  )
endif(WERROR)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_dissector_files(plugin.c
  plugin
  ${DISSECTOR_SRC}
  ${DISSECTOR_UTILITY_SRC}
)

if(WIRESHARK_FOUND)

  add_library(ffxiv
    ${LINK_MODE_MODULE}
    ${PLUGIN_FILES}
  )

  set_target_properties(ffxiv PROPERTIES PREFIX "")
  set_target_properties(ffxiv PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

  target_link_libraries(ffxiv wireshark gcrypt glib-2.0)

  install(TARGETS ffxiv
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} NAMELINK_SKIP
          RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

# This is broken on OSX, ignore for now
#
#  if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
#    add_custom_command(TARGET ffxiv
#      POST_BUILD
#      COMMAND ${CMAKE_STRIP} --strip-debug --strip-unneeded ffxiv.so
#    )
#  endif(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")

else(WIRESHARK_FOUND)

  include(WiresharkPlugin)
  set_module_info(ffxiv 0 0 1 0)

  add_plugin_library(ffxiv)

  install(TARGETS ffxiv
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
          RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
  )

  file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "src/*.h")

  CHECKAPI(
      NAME
        ffxiv
      SWITCHES
        -g abort -g termoutput -build
      SOURCES
        ${DISSECTOR_SRC}
        ${DISSECTOR_HEADERS}
  )

endif(WIRESHARK_FOUND)

