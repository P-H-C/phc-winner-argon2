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
SRC = src/argon2.c src/core.c src/kat.c src/blake2/blake2b-ref.c src/thread.c
SRC_MAIN = src/main.c
OBJ = $(SRC:.c=.o)

CFLAGS = -std=c99 -pthread -O3 -Wall -g
CFLAGS_OPT = $(CFLAGS) 

#OPT=TRUE
ifeq ($(OPT), TRUE)
	CFLAGS += -m64 -mavx
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
	LIB_PATH := -Wl,-rpath=$(BUILD_PATH)
endif
ifeq ($(KERNEL_NAME), Darwin)
	LIB_EXT := dylib
	LIB_CFLAGS := -dynamiclib -install_name @rpath/lib$(LIB_NAME).$(LIB_EXT)
	LIB_PATH := -Xlinker -rpath -Xlinker $(BUILD_PATH)
endif

LIB_SH := lib$(LIB_NAME).$(LIB_EXT)
LIB_ST := lib$(LIB_NAME).a

.PHONY: clean dist format 

all: clean bin libs
bin: $(BIN)
libs: $(LIB_SH) $(LIB_ST)

$(BIN): 	$(SRC) $(SRC_MAIN)
		$(CC) $(CFLAGS) $^ -Isrc  -o $@

$(LIB_SH): 	$(SRC)
		$(CC) $(CFLAGS) $(LIB_CFLAGS) $^ -Isrc -o $@

$(LIB_ST): 	$(OBJ)
		ar rcs $@ $^

clean:
		rm -f $(BIN) $(LIB_SH) $(LIB_ST) kat-argon2* 
		rm -rf *.dSYM
		cd src/ && rm -f *.o
		cd src/blake2/ && rm -f *.o
		cd test-vectors/ &&  rm -f kat-* diff* run_* make_*

dist:
		cd ..; \
		tar cfvJ $(DIST)/$(DIST)-`date "+%Y%m%d%H%M00"`.txz $(DIST)/*

format:
		clang-format -i src/*.c src/*.h src/blake2/*.c src/blake2/*.h
