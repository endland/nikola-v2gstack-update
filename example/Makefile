CC=clang
LD=clang
CFLAGS=-g -Os -Wall -pedantic
LDFLAGS=

TARGET=example.out

SOURCES=$(wildcard *.c slac/*.c)
OBJECTS=$(SOURCES:.c=.o)

LIBS=\
	-L..\
	-lnikolav2g_0.9.4\
	-lmultitask\
	-lOpenV2G_0.9.4\
	-lmbedtls\
  	-lmbedcrypto\
  	-lmbedx509\
	-lm\
	-lrt\
	-lpthread\

INCLUDES=-I..

all: $(TARGET)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all
