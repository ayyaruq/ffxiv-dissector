project(ffxiv-wireshark-dissector C)

cmake_minimum_required(VERSION 3.7)
set(CMAKE_BACKWARDS_COMPATIBILITY 3.7)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Wireshark)

if(WIRESHARK_FOUND)

  MESSAGE(STATUS "Wireshark libraries found, performing a stand-alone plug-in build.")

  if(NOT CMAKE_INSTALL_LIBDIR )
    set(CMAKE_INSTALL_LIBDIR ~/.wireshark/plugins)
  endif(NOT CMAKE_INSTALL_LIBDIR )
  MESSAGE(STATUS "Plug-in will be installed in: ${CMAKE_INSTALL_LIBDIR}")

  INCLUDE(UseMakeDissectorReg)
  INCLUDE(CMakeForceCompiler)

  set(GLIB2_MIN_VERSION 2.4.0)

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

  include_directories (${WIRESHARK_INCLUDE_DIRS})

  set(LINK_MODE_LIB SHARED)
  set(LINK_MODE_MODULE MODULE)

else(WIRESHARK_FOUND)

  MESSAGE(STATUS "Wireshark libraries not found, performing a Wireshark plug-in build.")

  include(WiresharkPlugin)
  set_module_info(ffxiv 0 0 0 1)

endif(WIRESHARK_FOUND)

set(DISSECTOR_SRC
	src/packet-ffxiv.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_dissector_files(plugin.c
	plugin
	${DISSECTOR_SRC}
        ${DISSECTOR_SUPPORT_SRC}
)

if(WIRESHARK_FOUND)

  add_library(ffxiv ${LINK_MODE_MODULE}
                  ${PLUGIN_FILES}
  )

  set_target_properties(ffxiv PROPERTIES PREFIX "")
  set_target_properties(ffxiv PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

  target_link_libraries(ffxiv wireshark)

  install(TARGETS ffxiv
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} NAMELINK_SKIP
#          RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
#          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

else(WIRESHARK_FOUND)

  add_plugin_library(ffxiv)

  install(TARGETS ffxiv
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
#          RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
#          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
  )

  file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
#  CHECKAPI(
#  	NAME
#  	  ffxiv
#  	SWITCHES
#  	  -g abort -g termoutput -build
#  	SOURCES
#  	  ${DISSECTOR_SRC}
#  	  ${DISSECTOR_HEADERS}
#  )
#
endif(WIRESHARK_FOUND)
