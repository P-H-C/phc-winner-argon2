#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#

RUN = argon2
BENCH = bench
GENKAT = genkat

DIST = phc-winner-argon2

SRC = src/argon2.c src/core.c src/blake2/blake2b.c src/thread.c src/encoding.c
SRC_RUN = src/run.c
SRC_BENCH = src/bench.c
SRC_GENKAT = src/genkat.c
OBJ = $(SRC:.c=.o)

CFLAGS += -std=c89 -pthread -O3 -Wall -g

#OPT=TRUE
ifeq ($(OPT), TRUE)
	CFLAGS += -march=native
	SRC += src/opt.c
else
	SRC += src/ref.c
endif

BUILD_PATH := $(shell pwd)
KERNEL_NAME := $(shell uname -s)

LIB_NAME=argon2
ifeq ($(KERNEL_NAME), Linux)
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
	SO_LDFLAGS := -Wl,-soname,libargon2.so.0
endif
ifeq ($(KERNEL_NAME), NetBSD)
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
endif
ifeq ($(KERNEL_NAME), Darwin)
	LIB_EXT := dylib
	LIB_CFLAGS := -dynamiclib -install_name @rpath/lib$(LIB_NAME).$(LIB_EXT)
endif
ifeq ($(findstring MINGW, $(KERNEL_NAME)), MINGW)
	LIB_EXT := dll
	LIB_CFLAGS := -shared -Wl,--out-implib,lib$(LIB_NAME).$(LIB_EXT).a
endif
ifeq ($(KERNEL_NAME), $(filter $(KERNEL_NAME),OpenBSD FreeBSD))
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
endif

LIB_SH := lib$(LIB_NAME).$(LIB_EXT)
LIB_ST := lib$(LIB_NAME).a

.PHONY: clean dist format $(GENKAT)

all: clean $(RUN) libs 
libs: $(LIB_SH) $(LIB_ST)

$(RUN):	        $(SRC) $(SRC_RUN)
		$(CC) $(CFLAGS) $(LDFLAGS) $^ -Isrc  -o $@

$(BENCH):       $(SRC) $(SRC_BENCH)
		$(CC) $(CFLAGS) $^ -Isrc  -o $@

$(GENKAT):      $(SRC) $(SRC_GENKAT)
		$(CC) $(CFLAGS) $^ -Isrc  -o $@ -DGENKAT

$(LIB_SH): 	$(SRC)
		$(CC) $(CFLAGS) $(LIB_CFLAGS) $(LDFLAGS) $(SO_LDFLAGS) $^ -Isrc -o $@

$(LIB_ST): 	$(OBJ)
		ar rcs $@ $^

clean:
		rm -f $(RUN) $(BENCH) $(GENKAT)
		rm -f $(LIB_SH) $(LIB_ST) kat-argon2* 
		rm -rf *.dSYM
		cd src/ && rm -f *.o
		cd src/blake2/ && rm -f *.o
		cd kats/ &&  rm -f kat-* diff* run_* make_*

dist:
		cd ..; \
		tar -c --exclude='.??*' -z -f $(DIST)-`date "+%Y%m%d"`.tgz $(DIST)/*

test:
		@sh kats/test.sh

format:
		clang-format -style="{BasedOnStyle: llvm, IndentWidth: 4}" -i src/*.c src/*.h src/blake2/*.c src/blake2/*.h
