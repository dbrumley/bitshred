EXTRA_DIST = quality/quality.py
bin_PROGRAMS = bitshred
bitshred_SOURCES = bitshred.c \
                   vdb.h vdb.c \
                   bincode.h bincode.c \
                   bs_common.h bs_common.c \
                   shred.h shred.c \
                   jaccard.h jaccard.c

AM_CFLAGS = -Wall -O3 -g
AM_LDFLAGS = -lbfd -ldb -lopcodes
