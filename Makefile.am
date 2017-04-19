include $(top_srcdir)/Makefile.am.inc
include ../Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = ffxiv

# Non-generated sources to be scanned for registration routines
DISSECTOR_SRC = \
  src/packet-ffxiv.c

#DISSECTOR_UTILITY_SRC = \

SRC_C_FILES = \
  $(DISSECTOR_SRC)
#  $(DISSECTOR_UTILITY_SRC)

# Headers
DISSECTOR_INCLUDES = \
  src/packet-ffxiv.h

#DISSECTOR_UTILITY_INCLUDES = \

HEADER_FILES = \
  $(DISSECTOR_INCLUDES)
#  $(DISSECTOR_UTILITY_INCLUDES)

plugin_LTLIBRARIES = libffxiv.la

ffxiv_la_SOURCES = \
  plugin.c \
  moduleinfo.h \
  $(SRC_C_FILES) \
  $(HEADER_FILES)

ffxiv_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

ffxiv_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

ffxiv_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
  ffxiv \
  *~

DISTCLEANFILES = \
  plugin.c

MAINTAINERCLEANFILES = \
  Makefile.in

EXTRA_DIST = \
  CMakeLists.txt
