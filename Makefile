BIN := wifight
CFLAGS := -O2 -Wall
LDFLAGS := -lpcap

all: $(BIN)

$(BIN): $(BIN).c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean::
	$(RM) $(BIN)
