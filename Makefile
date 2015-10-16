#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#

CC = gcc
BIN = argon2
REF_CFLAGS = -std=c99 -pthread -O3 -Wall -Wno-unused-function
OPT_CFLAGS = $(REF_FLAGS) -m64 -mavx

ARGON2_DIR = src
BLAKE2_DIR = src/blake2
BUILD_DIR = build

ARGON2_SRC = argon2.c argon2-core.c kat.c
BLAKE2_SRC = blake2b-ref.c
OPT_SRC = argon2-opt-core.c
REF_SRC = argon2-ref-core.c
TEST_SRC = argon2-test.c


ARGON2_BUILD_SRC = $(addprefix $(ARGON2_DIR)/,$(ARGON2_SRC))
BLAKE2_BUILD_SRC = $(addprefix $(BLAKE2_DIR)/,$(BLAKE2_SRC))
TEST_BUILD_SRC = $(addprefix $(ARGON2_DIR)/,$(TEST_SRC))


#OPT=TRUE
ifeq ($(OPT), TRUE)
	CFLAGS=$(OPT_CFLAGS)
	ARGON2_BUILD_SRC += $(addprefix $(ARGON2_DIR)/,$(OPT_SRC))
else
	CFLAGS=$(REF_CFLAGS)
	ARGON2_BUILD_SRC += $(addprefix $(ARGON2_DIR)/,$(REF_SRC))
endif


SRC_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

BUILD_DIR_PATH := $(shell pwd)

SYSTEM_KERNEL_NAME := $(shell uname -s)

LIB_NAME=argon2
ifeq ($(SYSTEM_KERNEL_NAME), Linux)
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
	LIB_PATH := -Wl,-rpath=$(BUILD_DIR_PATH)
endif
ifeq ($(SYSTEM_KERNEL_NAME), Darwin)
	LIB_EXT := dylib
	LIB_CFLAGS := -dynamiclib -install_name @rpath/lib$(LIB_NAME).$(LIB_EXT)
	LIB_PATH := -Xlinker -rpath -Xlinker $(BUILD_DIR_PATH)
endif

LIB := lib$(LIB_NAME).$(LIB_EXT)

.PHONY: clean test

all: clean $(BIN) $(LIB)

$(BIN):
	$(CC) $(CFLAGS) \
            $(ARGON2_BUILD_SRC) $(BLAKE2_BUILD_SRC) $(TEST_BUILD_SRC) \
	    -I$(ARGON2_DIR) -I$(BLAKE2_DIR) -o $@

$(LIB):
	$(CC) $(CFLAGS) $(LIB_CFLAGS) \
            $(ARGON2_BUILD_SRC) $(BLAKE2_BUILD_SRC) \
	    -I$(ARGON2_DIR) -I$(BLAKE2_DIR) -o $@

test:   
	./test.sh -src=$(SRC_DIR)

clean:
	rm -f $(BIN) $(LIB) kat-argon2* 
	cd tests &&  rm -f kat-* diff* run_*
