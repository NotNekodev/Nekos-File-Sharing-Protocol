CC = gcc
CFLAGS = -I../../include -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

SERVER_SRC := $(wildcard ../../src/server/*.c)
COMMON_SRC := $(wildcard ../../src/common/*.c)

SERVER_OBJ := $(patsubst ../../src/server/%.c, ../../build/server/%.o, $(SERVER_SRC))
COMMON_OBJ := $(patsubst ../../src/common/%.c, ../../build/common/%.o, $(COMMON_SRC))

OBJS := $(SERVER_OBJ) $(COMMON_OBJ)

TARGET = ../../build/server/nfsp_server	

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile server sources
../../build/server/%.o: ../../src/server/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile common sources
../../build/common/%.o: ../../src/common/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
