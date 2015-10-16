#
# Argon2 source code package
# 
# This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
# 
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
#

CC = gcc
REF_CFLAGS = -std=c99 -pthread -O3 -Wall
OPT_CFLAGS = -std=c99 -pthread -O3 -m64 -mavx -Wall

ARGON2_DIR = ./src/
BLAKE2_DIR = ./src/blake2/
BUILD_DIR = ./build/
TEST_DIR = ./test/

ARGON2_SOURCES = argon2.c argon2-core.c kat.c
BLAKE2_SOURCES = blake2b-ref.c
TEST_SOURCES = argon2-test.c

REF_SOURCES = argon2-ref-core.c
OPT_SOURCES = argon2-opt-core.c

LIB_NAME=argon2

ARGON2_BUILD_SOURCES = $(addprefix $(ARGON2_DIR)/,$(ARGON2_SOURCES))
BLAKE2_BUILD_SOURCES = $(addprefix $(BLAKE2_DIR)/,$(BLAKE2_SOURCES))
TEST_BUILD_SOURCES = $(addprefix $(ARGON2_DIR)/,$(TEST_SOURCES))


#OPT=TRUE
ifeq ($(OPT), TRUE)
	CFLAGS=$(OPT_CFLAGS)
	ARGON2_BUILD_SOURCES += $(addprefix $(ARGON2_DIR)/,$(OPT_SOURCES))
else
	CFLAGS=$(REF_CFLAGS)
	ARGON2_BUILD_SOURCES += $(addprefix $(ARGON2_DIR)/,$(REF_SOURCES))
endif


SRC_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

BUILD_DIR_PATH := $(shell pwd)/$(BUILD_DIR)

SYSTEM_KERNEL_NAME := $(shell uname -s)

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


.PHONY: clean argon2-genkat argon2-lib test

all:  argon2 argon2-genkat argon2-lib 

argon2:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) \
		$(ARGON2_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		$(TEST_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-o $(BUILD_DIR)/$@

argon2-genkat:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) \
		-DARGON2_KAT -DARGON2_KAT_INTERNAL \
		$(ARGON2_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		$(TEST_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-o $(BUILD_DIR)/$@

argon2-lib:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) \
		$(LIB_CFLAGS) \
		$(ARGON2_BUILD_SOURCES) \
		$(BLAKE2_BUILD_SOURCES) \
		-I$(ARGON2_DIR) \
		-I$(BLAKE2_DIR) \
		-o $(BUILD_DIR)/lib$(LIB_NAME).$(LIB_EXT)

test:   argon2-genkat
	./check_test_vectors.sh -src=$(SRC_DIR)

clean:
	rm -rf $(BUILD_DIR)/
	rm -f $(TEST_DIR)/run_*
