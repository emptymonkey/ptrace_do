CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -pedantic -O3
AR = ar
ARFLAGS = rcs
RANLIB = ranlib

all: libptrace_do.a test

libptrace_do.a: libptrace_do.c libptrace_do.h
	$(CC) $(CFLAGS) -c libptrace_do.c
	$(AR) $(ARFLAGS) libptrace_do.a libptrace_do.o
	$(RANLIB) libptrace_do.a

test: test.c
	$(CC) $(CFLAGS) -L. -o test test.c -lptrace_do

clean: 
	rm libptrace_do.o libptrace_do.a test
