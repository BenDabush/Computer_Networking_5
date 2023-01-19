CC = gcc
AR = ar
CFLAGS = -g -Wall 
ALL_OBJFILES = Gateway Sniffer Spoofer Gateway.o Sniffer.o Spoofer.o


all : $(ALL_OBJFILES)

Sniffer: Sniffer.o
	$(CC) $(CFLAGS) Sniffer.c -o Sniffer -lpcap

Spoofer: Spoofer.o
	$(CC) $(CFLAGS) Spoofer.c -o Spoofer

Gateway: Gateway.o 	
	$(CC) $(CFLAGS) Gateway.c -o Gateway

Spoofer.o: Spoofer.c
	$(CC) $(CFLAGS) -c Spoofer.c 

Gateway.o: Gateway.c
	$(CC) $(CFLAGS) -c Gateway.c
	
.PHONY: clean all

clean:
	rm -f *.o $(ALL_OBJFILES)