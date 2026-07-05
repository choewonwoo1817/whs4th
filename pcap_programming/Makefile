CC      = gcc
CFLAGS  = -Wall -O2
LDFLAGS = -lpcap
TARGET  = pcap_prog

$(TARGET): pcap_prog.c myheader.h
	$(CC) $(CFLAGS) -o $(TARGET) pcap_prog.c $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
