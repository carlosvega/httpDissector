HPCAPDIR=HPCAP4
PACKETFEEDERDIR=../packet_feeder_shrmem

CC = gcc

ifeq (, $(shell which clang))
$(warning CLANG NOT FOUND, SWITCHING TO GCC)
CC = gcc
endif

PRECFLAGS = $(CC) -Wall -mtune=native -march=native -O3 -D_GNU_SOURCE -Iinclude/ 
CFLAGS = $(PRECFLAGS)  -flto
LDFLAGS = -lm -lpthread -lpcap  -flto

OS := $(shell uname -s)
ifeq ($(OS),Linux)
LFLAGS += -lrt
endif

HPCAPFLAGS = -lhpcap

HPCAP_DIR = -L$(HPCAPDIR)/lib -I$(HPCAPDIR)/include
LIB_DIR = -L$(PACKETFEEDERDIR) -I$(PACKETFEEDERDIR)

PCAPLIB		= -lpcap

LOW_MEMORY: CFLAGS = $(PRECFLAGS) -D LOW_MEMORY_DISSECTOR
HPCAP: CFLAGS = $(PRECFLAGS) -D HPCAP_SUPPORT 

all: httpDissector

list.o: list.c
	$(CFLAGS) -c $^ -o $@
counters.o: counters.c
	$(CFLAGS) -c $^ -o $@
alist.o: alist.c
	$(CFLAGS) -c $^ -o $@
http.o: http.c
	$(CFLAGS) -c $^ -o $@
tools.o: tools.c
	$(CFLAGS) -c $^ -o $@
#NEW DISSECTOR
process_packet.o: process_packet.c
	$(CFLAGS) -c $^ -o $@
hash_table.o: hash_table.c
	$(CFLAGS) -c $^ -o $@
http_event_pool.o: http_event_pool.c
	$(CFLAGS) -c $^ -o $@
collision_list_pool.o: collision_list_pool.c
	$(CFLAGS) -c $^ -o $@
httpDissector: httpDissector.c hash_table.o collision_list_pool.o counters.o http_event_pool.o process_packet.o alist.o tools.o http.o NDleeTrazas.o args_parse.o
	$(CFLAGS)  -c httpDissector.c -o httpDissector.o
	$(CFLAGS)  $^ -o $@ $(PCAPLIB) $(LDFLAGS)
httpDissector_wormhole: httpDissector.c hash_table.o collision_list_pool.o http_event_pool.o process_packet.o alist.o tools.o http.o args_parse.o hpcap_utils.o worm_pcap_bridge.c
	$(CFLAGS)  -I../../../include -c httpDissector.c -o httpDissector.o
	$(CFLAGS) -I../../../include  $(LIB_DIR) $^ -o $@ $(PCAPLIB) $(LDFLAGS) -L../../../lib -lworm
httpDissector_packetFeeder: httpDissector.c tools.o http.o alist.o hash_table.o collision_list_pool.o http_event_pool.o process_packet.o ../packet_feeder_shrmem/packet_feeder_NDLT.o args_parse.o hpcap_utils.o lib/libmgmon.c ../packet_feeder_shrmem/packet_buffers.o
	$(MAKE) -C $(PACKETFEEDERDIR)
	$(CFLAGS)  -c httpDissector.c -o httpDissector.o
	$(CFLAGS)  $(LIB_DIR) $^ -o $@ $(PCAPLIB) $(LDFLAGS) -lrt -lmgmon -lhpcap
NDleeTrazas.o: NDleeTrazas.c
	$(CFLAGS) -std=gnu99 -c NDleeTrazas.c -o NDleeTrazas.o
args_parse.o: args_parse.c
	$(CFLAGS) -c $^ -o $@
clean:	
	rm -f *.o httpDissector httpDissector_packetFeeder
