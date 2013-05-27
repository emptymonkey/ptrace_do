CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -pedantic -O3
AR = ar
ARFLAGS = rcs
RANLIB = ranlib

all: libptrace_do.a driver

libptrace_do.a: libptrace_do.c libptrace_do.h
	$(CC) $(CFLAGS) -c libptrace_do.c
	$(AR) $(ARFLAGS) libptrace_do.a libptrace_do.o
	$(RANLIB) libptrace_do.a

driver: 
	$(CC) $(CFLAGS) -L. -o driver driver.c -lptrace_do

clean: 
	rm libptrace_do.o libptrace_do.a driver
