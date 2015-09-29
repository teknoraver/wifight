BIN := wifight
CFLAGS ?= -O2 -Wall
LDLIBS := -lpcap

all: $(BIN)

clean::
	$(RM) $(BIN)
