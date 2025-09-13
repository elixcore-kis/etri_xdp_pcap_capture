CC = gcc
CLANG = clang

CFLAGS = -Wall -Wextra -O2
BPF_CFLAGS = -O2 -g -Wall \
			 -Wno-unused-value -Wno-pointer-sign \
			 -Wno-compare-distinct-pointer-types \
			 -I/usr/include

LIBS = -lbpf

# Original ring buffer implementation
XDP_TARGET = xdp_capture
XDP_OBJ = $(XDP_TARGET).o
USERSPACE_TARGET = capture_main

# AF_XDP implementation
AFXDP_XDP_TARGET = xdp_afxdp
AFXDP_XDP_OBJ = $(AFXDP_XDP_TARGET).o
AFXDP_USERSPACE_TARGET = afxdp_capture
AFXDP_SIMPLE_TARGET = afxdp_capture_simple

.PHONY: all clean test afxdp

all: $(USERSPACE_TARGET) $(XDP_OBJ)

afxdp: $(AFXDP_USERSPACE_TARGET) $(AFXDP_XDP_OBJ)

afxdp-simple: $(AFXDP_SIMPLE_TARGET) $(AFXDP_XDP_OBJ)

$(XDP_OBJ): $(XDP_TARGET).c
	$(CLANG) $(BPF_CFLAGS) -target bpf -c $< -o $@

$(USERSPACE_TARGET): $(USERSPACE_TARGET).c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

$(AFXDP_XDP_OBJ): $(AFXDP_XDP_TARGET).c
	$(CLANG) $(BPF_CFLAGS) -target bpf -c $< -o $@

$(AFXDP_USERSPACE_TARGET): $(AFXDP_USERSPACE_TARGET).c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

$(AFXDP_SIMPLE_TARGET): $(AFXDP_SIMPLE_TARGET).c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(USERSPACE_TARGET) $(XDP_OBJ) $(AFXDP_USERSPACE_TARGET) $(AFXDP_SIMPLE_TARGET) $(AFXDP_XDP_OBJ) *.pcap

test: all
	@echo "Build completed successfully!"
	@echo "Usage: sudo ./$(USERSPACE_TARGET) <interface> <output_file.pcap>"
	@echo "Example: sudo ./$(USERSPACE_TARGET) ens20 capture.pcap"

test-afxdp: afxdp
	@echo "AF_XDP build completed successfully!"
	@echo "Usage: sudo ./$(AFXDP_USERSPACE_TARGET) <interface> <output_file.pcap>"
	@echo "Example: sudo ./$(AFXDP_USERSPACE_TARGET) ens20 afxdp_capture.pcap"

install: all test

.DEFAULT_GOAL := all