CC = gcc
AR = ar
CFLAGS = -g -Wall 
ALL_OBJFILES = Gateway Sniffer Spoofer Sniffer_Spoofer Gateway.o Sniffer.o Spoofer.o Sniffer_Spoofer.o


all : $(ALL_OBJFILES)

Sniffer: Sniffer.o
	$(CC) $(CFLAGS) Sniffer.c -o Sniffer -lpcap

Spoofer: Spoofer.o
	$(CC) $(CFLAGS) Spoofer.c -o Spoofer

Gateway: Gateway.o 	
	$(CC) $(CFLAGS) Gateway.c -o Gateway

Sniffer_Spoofer: Sniffer_Spoofer.o
	$(CC) $(CFLAGS) Sniffer_Spoofer.c -o Sniffer_Spoofer -lpcap
	
.PHONY: clean all

clean:
	rm -f *.o $(ALL_OBJFILES)