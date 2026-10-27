CC = gcc
CFLAGS = -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -g -Iinclude

TARGET = cn-core
SOURCES = src/main.c src/frame.c
GUI_SOURCES = src/gui.c src/frame.c src/ipv4.c src/ipv6.c src/transport.c src/stats.c src/icmp.c src/arp.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES) include/lib.h
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

gui: $(GUI_SOURCES) include/lib.h include/ipv4.h include/ipv6.h include/transport.h include/icmp.h include/arp.h include/stats.h
	$(CC) $(CFLAGS) $$(pkg-config --cflags gtk4 libpcap) $(GUI_SOURCES) -o $@ $$(pkg-config --libs gtk4 libpcap)

capture: src/capture.c src/frame.c src/ipv4.c src/ipv6.c src/transport.c src/stats.c src/icmp.c src/arp.c
	$(CC) $(CFLAGS) -o capture src/capture.c src/frame.c src/ipv4.c src/ipv6.c src/icmp.c src/arp.c src/transport.c src/stats.c $$(pkg-config --cflags --libs libpcap)

interfaces: src/interfaces.c
	$(CC) $(CFLAGS) src/interfaces.c -o interfaces $$(pkg-config --cflags --libs libpcap)

test-frame: tests/test_frame.c src/frame.c include/lib.h
	$(CC) $(CFLAGS) tests/test_frame.c src/frame.c -o test-frame
	./test-frame

test-stats: tests/test_stats.c src/stats.c src/frame.c include/lib.h include/stats.h
	$(CC) $(CFLAGS) tests/test_stats.c src/stats.c src/frame.c -o test-stats
	./test-stats

clean:
	rm -f $(TARGET) framescope-gui capture interfaces test-frame test-stats
