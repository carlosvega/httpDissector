HPCAPDIR=HPCAP4
PACKETFEEDERDIR=../packet_feeder_shrmem

CC = gcc #clang

ifeq (, $(shell which clang))
$(warning CLANG NOT FOUND, SWITCHING TO GCC)
CC = gcc
endif

PRECFLAGS = $(CC) -O3 -Wall -D_GNU_SOURCE -Iinclude/ 
CFLAGS = $(PRECFLAGS)
LDFLAGS = -lm -lpthread -lpcap

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

all: httpDissector #indice_traza #httpDissector_wormhole

indice_traza: main_indiceTraza.c
	$(CFLAGS) -std=gnu99 main_indiceTraza.c NDleeTrazas.c -lpcap -o $@
sampling_index.o: sampling_index.c
	$(CFLAGS) -c $^ -o $@
list.o: list.c
	$(CFLAGS) -c $^ -o $@
sorted_print.o: sorted_print.c
	$(CFLAGS) -c $^ -o $@
IPflow.o: IPflow.c
	$(CFLAGS) -c $^ -o $@
counters.o: counters.c
	$(CFLAGS) -c $^ -o $@
index.o: index.c
	$(CFLAGS) -c $^ -o $@
request.o: request.c
	$(CFLAGS) -c $^ -o $@
response.o: response.c
	$(CFLAGS) -c $^ -o $@
connection.o: connection.c
	$(CFLAGS) -c $^ -o $@
alist.o: alist.c
	$(CFLAGS) -c $^ -o $@
http.o: http.c
	$(CFLAGS) -c $^ -o $@
tools.o: tools.c
	$(CFLAGS) -c $^ -o $@
hpcap_utils.o: hpcap_utils.c
	$(CFLAGS) -c $^ -o $@ 
httpDissector: httpDissector.c sampling_index.o counters.o index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o NDleeTrazas.o args_parse.o hpcap_utils.o
	$(CFLAGS)  -c httpDissector.c -o httpDissector.o
	$(CFLAGS)  $^ -o $@ $(PCAPLIB) $(LDFLAGS)
LOW_MEMORY: httpDissector.c sampling_index.o counters.o index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o NDleeTrazas.o args_parse.o hpcap_utils.o
	@echo "WARNING: COMPILING LOW_MEMORY VERSION. The size of the pools are reduced. This could lead to an expected behaviour."
	$(CFLAGS)  -c httpDissector.c -o httpDissector.o
	$(CFLAGS)  $^ -o httpDissector $(PCAPLIB) $(LDFLAGS)
HPCAP: httpDissector.c sampling_index.o counters.o index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o NDleeTrazas.o args_parse.o hpcap_utils.o lib/libmgmon.c
	@echo "INFO: COMPILING HPCAP VERSION..."
	$(CFLAGS)  -c httpDissector.c -o httpDissector.o
	$(CFLAGS)  $(HPCAP_DIR) $^ -o httpDissector $(PCAPLIB) $(HPCAPFLAGS) $(LDFLAGS)
httpDissector_packetFeeder: httpDissector.c sampling_index.o counters.o index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o ../packet_feeder_shrmem/packet_feeder_NDLT.o args_parse.o hpcap_utils.o lib/libmgmon.c ../packet_feeder_shrmem/packet_buffers.o
	$(MAKE) -C $(PACKETFEEDERDIR)
	$(CFLAGS)  -c httpDissector.c -o httpDissector.o
	$(CFLAGS)  $(LIB_DIR) $^ -o $@ $(PCAPLIB) $(LDFLAGS)
httpDissector_wormhole: httpDissector.c sampling_index.o counters.o index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o worm_pcap_bridge.c args_parse.o hpcap_utils.o  ../../../lib/libworm.so 
	$(CFLAGS) -I../../../include -I../hptimelib/include -c httpDissector.c -o httpDissector.o -D LOW_MEMORY_DISSECTOR
	$(CFLAGS) -I../../../include -I../hptimelib/include $(LIB_DIR) $^ -o $@ $(PCAPLIB) $(LDFLAGS) -L../../../lib -lworm -D LOW_MEMORY_DISSECTOR ../hptimelib/lib/hptl.a
NDleeTrazas.o: NDleeTrazas.c
	$(CFLAGS) -std=gnu99 -c NDleeTrazas.c -o NDleeTrazas.o
args_parse.o: args_parse.c
	$(CFLAGS) -c $^ -o $@
clean:	
	rm -f *.o httpDissector httpDissector_packetFeeder NDleeTrazas indiceTraza
