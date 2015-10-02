BIN := wifight
CFLAGS ?= -O2 -Wall

all: $(BIN)

clean::
	$(RM) $(BIN)
