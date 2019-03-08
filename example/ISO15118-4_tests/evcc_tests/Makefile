CC=clang
LD=clang
CFLAGS=-g -Os -Wall -pedantic
LDFLAGS=

TARGET=evcc_test

SOURCES=\
	../../server.c\
    $(wildcard *.c)\

HEADERS=\

OBJECTS=\
    $(SOURCES:.c=.o)\

LIBS=\
	-L../..\
	-lnikolav2g_0.9.4\
	-lmultitask\
	-lOpenV2G_0.9.4\
	-lmbedtls\
	-lmbedx509\
	-lmbedcrypto\
	-lm\
	-lrt\
	-lpthread\

INCLUDES=-I../..\

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGET)

all: $(TARGET)
