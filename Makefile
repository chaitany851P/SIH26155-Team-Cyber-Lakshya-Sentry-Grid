# ==============================================================================
# SENTRY-GRID Makefile for Linux & Windows (MinGW-w64)
# ==============================================================================

CC ?= gcc
CFLAGS ?= -O3 -Wall -Wextra -fPIC
SRC_DIR = src_native
BIN_DIR = bin

SRCS = $(SRC_DIR)/sentry_crypto.c \
       $(SRC_DIR)/sentry_vector.c \
       $(SRC_DIR)/sentry_lexer.c \
       $(SRC_DIR)/sentry_policy.c \
       $(SRC_DIR)/sentry_core.c

ifeq ($(OS),Windows_NT)
    TARGET_LIB = $(BIN_DIR)/sentry_native.dll
    TARGET_CLI = $(BIN_DIR)/sentry_cli.exe
    LDFLAGS_LIB = -shared -DSENTRY_EXPORTS
else
    TARGET_LIB = $(BIN_DIR)/libsentry_native.so
    TARGET_CLI = $(BIN_DIR)/sentry_cli
    LDFLAGS_LIB = -shared -DSENTRY_EXPORTS -lm
endif

.PHONY: all clean test

all: $(BIN_DIR) $(TARGET_LIB) $(TARGET_CLI)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(TARGET_LIB): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS_LIB) -o $@ $(SRCS)

$(TARGET_CLI): $(SRCS)
	$(CC) $(CFLAGS) -DSENTRY_CLI_APP -o $@ $(SRCS) -lm

clean:
	rm -rf $(BIN_DIR)

test: all
	./$(TARGET_CLI) samples/cisco_ios_xe_sample.cfg
