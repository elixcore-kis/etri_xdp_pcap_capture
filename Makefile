CC = gcc
CLANG = clang

CFLAGS = -Wall -Wextra -O2
BPF_CFLAGS = -O2 -g -Wall \
			 -Wno-unused-value -Wno-pointer-sign \
			 -Wno-compare-distinct-pointer-types \
			 -I/usr/include

LIBS = -lbpf

XDP_TARGET = xdp_capture
XDP_OBJ = $(XDP_TARGET).o
USERSPACE_TARGET = capture_main

.PHONY: all clean test

all: $(USERSPACE_TARGET) $(XDP_OBJ)

$(XDP_OBJ): $(XDP_TARGET).c
	$(CLANG) $(BPF_CFLAGS) -target bpf -c $< -o $@

$(USERSPACE_TARGET): $(USERSPACE_TARGET).c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(USERSPACE_TARGET) $(XDP_OBJ) *.pcap

test: all
	@echo "Build completed successfully!"
	@echo "Usage: sudo ./$(USERSPACE_TARGET) <interface> <output_file.pcap>"
	@echo "Example: sudo ./$(USERSPACE_TARGET) ens20 capture.pcap"

install: all test

.DEFAULT_GOAL := all