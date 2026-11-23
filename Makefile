# Needs liburing-dev:  sudo apt install liburing-dev
CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -g
LDLIBS  = -luring

workload: workload.c
	$(CC) $(CFLAGS) -o workload workload.c $(LDLIBS)

clean:
	rm -f workload

.PHONY: clean
