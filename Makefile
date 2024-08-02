CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap

all: pcap

pcap: main.o
	$(CC) -o $@ $^ $(LDFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f *.o pcap
