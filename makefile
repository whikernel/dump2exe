CC = gcc
LD = gcc

CFLAGS = -Wall -pipe 
OFLAGS = -c -I/usr/include -I/usr/lib/openssl
LFLAGS = $(CFLAGS) -L/usr/lib/ -L/usr/lib/ssl -lssl -lcrypto 

SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:.c=.o)

DEBUG = no
PROFILE = no
PEDANTIC = no
OPTIMIZATION = -g

ifeq ($(DEBUG), yes)
	CFLAGS += -g
	OPTIMIZATION = -O0
endif

ifeq ($(PROFILE), yes)
	CFLAGS += -pg
endif

CFLAGS += $(OPTIMIZATION)

all: dump2exe

dump2exe: $(OBJECTS)
	$(CC) $(OBJECTS) $(LFLAGS) -o bin/dump2exe

%.o: %.c
	$(CC) $(LFLAGS) -c $< -o $@

clean:
	rm -rf src/*.o bin/dump2exe

rebuild: clean all

.PHONY : clean
.SILENT : clean