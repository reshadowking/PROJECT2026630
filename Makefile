CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap -lpthread
OBJ = main.o capture.o parser.o traffic_stat.o tcp_reassemble.o tls_sni.o
TARGET = sniffer

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c common.h capture.h parser.h traffic_stat.h tcp_reassemble.h tls_sni.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o $(TARGET)