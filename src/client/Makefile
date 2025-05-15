CC = gcc
CFLAGS = -I../../include -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

CLIENT_SRC := $(wildcard ../../src/client/*.c)
COMMON_SRC := $(wildcard ../../src/common/*.c)

CLIENT_OBJ := $(patsubst ../../src/client/%.c, ../../build/client/%.o, $(CLIENT_SRC))
COMMON_OBJ := $(patsubst ../../src/common/%.c, ../../build/common/%.o, $(COMMON_SRC))

OBJS := $(CLIENT_OBJ) $(COMMON_OBJ)

TARGET = ../../build/client/nfsp_client

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile client sources
../../build/client/%.o: ../../src/client/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile common sources
../../build/common/%.o: ../../src/common/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
