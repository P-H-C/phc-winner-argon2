#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#

BIN = argon2
DIST = phc-winner-argon2

CC = gcc
SRC = src/argon2.c src/argon2-core.c src/kat.c src/blake2/blake2b-ref.c
SRC_MAIN = src/argon2-test.c

CFLAGS = -std=c99 -pthread -O3 -Wall
CFLAGS_OPT = $(CFLAGS) 

#OPT=TRUE
ifeq ($(OPT), TRUE)
	CFLAGS += -m64 -mavx
	SRC += src/argon2-opt-core.c
else
	SRC += src/argon2-ref-core.c
endif


BUILD_PATH := $(shell pwd)
KERNEL_NAME := $(shell uname -s)

LIB_NAME=argon2
ifeq ($(KERNEL_NAME), Linux)
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
	LIB_PATH := -Wl,-rpath=$(BUILD_PATH)
endif
ifeq ($(KERNEL_NAME), Darwin)
	LIB_EXT := dylib
	LIB_CFLAGS := -dynamiclib -install_name @rpath/lib$(LIB_NAME).$(LIB_EXT)
	LIB_PATH := -Xlinker -rpath -Xlinker $(BUILD_PATH)
endif

LIB := lib$(LIB_NAME).$(LIB_EXT)

.PHONY: clean test

all: clean $(BIN) $(LIB)

$(BIN): $(SRC) $(SRC_MAIN)
	$(CC) $(CFLAGS) $^ -Isrc -Isrc/blake2 -o $@

$(LIB): $(SRC)
	$(CC) $(CFLAGS) $(LIB_CFLAGS) $^ -Isrc -Isrc/blake2 -o $@

clean:
	rm -f $(BIN) $(LIB) kat-argon2* 
	cd test-vectors/ &&  rm -f kat-* diff* run_* make_*

dist:
	cd ..; \
	tar cfvJ $(DIST)/$(DIST)-`date "+%Y%m%d%H%M00"`.txz $(DIST)/*
