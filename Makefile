CC := gcc
LDFLAGS := -lutil

TARGET := ncshell

all: $(TARGET)

$(TARGET): ncshell.c
	$(CC) -g -o $@ $< $(LDFLAGS)

clean:
	-@rm -f $(TARGET)

.PHONY: all clean