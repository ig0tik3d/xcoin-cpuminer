
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= minerd

minerd_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  sha2.c sha2-arm.S sha2-x86.S sha2-x64.S \
		  scrypt.c scrypt-arm.S scrypt-x86.S scrypt-x64.S \
		  blake.c bmw.c	groestl.c jh.c keccak.c skein.c \
		  aes_helper.c cubehash.c shavite.c simd.c echo.c luffa.c\
		  quark.c Xcoin.c
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@

