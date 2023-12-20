#
# Makefile for libsignal extension module
#
EXT=1.4
EXTDIR=/home/user/lpc-ext
DEFINES=			# -DLARGENUM
CCFLAGS=$(DEFINES) -O2
CC=cc

CFLAGS=	-fPIC -DPIC $(CCFLAGS)
LD=$(CC)
LDFLAGS=-shared $(DEBUG)

all:	$(EXTDIR)/libsignal.$(EXT)


libsignal.o:	libsignal.c $(EXTDIR)/src/lpc_ext.h
	$(CC) -o $@ -c $(CFLAGS) -I. -I$(EXTDIR)/src libsignal.c

$(EXTDIR)/libsignal.$(EXT):	libsignal.o $(EXTDIR)/src/lpc_ext.o
	$(LD) -o $@ $(LDFLAGS) $+ -lcrypto

clean:
	rm -f $(EXTDIR)/libsignal.$(EXT) *.o
