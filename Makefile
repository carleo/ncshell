CC := gcc
LDFLAGS := -lutil -lpthread

TARGET := ncshell

all: $(TARGET)

$(TARGET): ncshell.c
	$(CC) -o $@ $< $(LDFLAGS)

clean:
	-@rm -f $(TARGET)

.PHONY: all clean