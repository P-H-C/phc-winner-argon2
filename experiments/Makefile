# Standalone builds for the Argon2 HPC experiments.
#
# This builds experiments/thp_bench and experiments/digest_check by compiling
# the unmodified Argon2 sources from the repository root (the same code that
# `make test` validates). Only the optimized (opt.c) or reference (ref.c)
# implementation is linked, mirroring the repository Makefile's selection
# logic; nothing in src/ or include/ is modified.
#
# Two flavours of every binary are produced:
#   <name>      baseline build
#   <name>_pw   identical build, adding only -DARGON2_EXPERIMENT_PERSISTENT_WORKERS
# Both flavours use exactly the same -O3 (and -march=native on AVX2-capable
# hosts) flags; the single extra define is the only difference.

CC ?= cc

CPPFLAGS += -I../include -Isrc
CFLAGS ?= -O3 -Wall -Wextra -pthread
CFLAGS += -D_GNU_SOURCE -std=c11

OPT ?= native
OPT_TEST := $(shell $(CC) -I../include -Isrc -march=$(OPT) ../src/opt.c -c \
			-o /dev/null 2>/dev/null; echo $$?)
ifeq ($(OPT_TEST), 0)
$(info experiments: building with optimized implementation for $(OPT))
	CFLAGS += -march=$(OPT)
	SRC_IMPL := ../src/opt.c
else
$(info experiments: building with reference implementation)
	SRC_IMPL := ../src/ref.c
endif

SRC = ../src/argon2.c ../src/core.c ../src/blake2/blake2b.c \
	  ../src/thread.c ../src/encoding.c $(SRC_IMPL)

# The only difference between baseline and experimental builds.
PW_FLAGS = -DARGON2_EXPERIMENT_PERSISTENT_WORKERS

# Adds an opt-in stderr line whenever the persistent path runs, used only to
# prove on the target node that the experiment is active (not for timing).
PW_DEBUG_FLAGS = $(PW_FLAGS) -DARGON2_EXPERIMENT_PERSISTENT_WORKERS_DEBUG

BENCHES = thp_bench thp_bench_pw digest_check digest_check_pw \
	  digest_check_pwdbg

.PHONY: all clean
all: $(BENCHES)

thp_bench: thp_bench.c $(SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) thp_bench.c $(SRC) -o $@

thp_bench_pw: thp_bench.c $(SRC)
	$(CC) $(CFLAGS) $(PW_FLAGS) $(CPPFLAGS) $(LDFLAGS) thp_bench.c $(SRC) -o $@

digest_check: digest_check.c $(SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) digest_check.c $(SRC) -o $@

digest_check_pw: digest_check.c $(SRC)
	$(CC) $(CFLAGS) $(PW_FLAGS) $(CPPFLAGS) $(LDFLAGS) digest_check.c $(SRC) -o $@

digest_check_pwdbg: digest_check.c $(SRC)
	$(CC) $(CFLAGS) $(PW_DEBUG_FLAGS) $(CPPFLAGS) $(LDFLAGS) digest_check.c $(SRC) -o $@

clean:
	rm -f $(BENCHES)
	rm -rf *.dSYM
