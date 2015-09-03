HPCAPDIR=HPCAP4
PACKETFEEDERDIR=../packet_feeder_shrmem

CC = gcc -g -Wall -D_GNU_SOURCE -Iinclude/ 
CC_LOW = gcc -g -Wall -D_GNU_SOURCE -D LOW_MEMORY_DISSECTOR -Iinclude/ 
CC_HPCAP = gcc -g -Wall -D_GNU_SOURCE -D HPCAP_SUPPORT -Iinclude/
LDFLAGS = -lm -lpthread -lpcap -lrt
HPCAPFLAGS = -lhpcap

HPCAP_DIR = -L$(HPCAPDIR)/lib -I$(HPCAPDIR)/include
LIB_DIR = -L$(PACKETFEEDERDIR) -I$(PACKETFEEDERDIR)

PCAPLIB		= -lpcap

all: httpDissector indice_traza

indice_traza: main_indiceTraza.c
	$(CC) -std=gnu99 main_indiceTraza.c NDleeTrazas.c -lpcap -o $@
err_mqueue: err_mqueue.c
	$(CC) -c -lpthread err_mqueue.c -o err_mqueue.o
sampling_index.o: sampling_index.c
	$(CC) -c $^ -o $@
list.o: list.c
	$(CC) -c $^ -o $@
sorted_print.o: sorted_print.c
	$(CC) -c $^ -o $@
IPflow.o: IPflow.c
	$(CC) -c $^ -o $@
counters.o: counters.c
	$(CC) -c $^ -o $@
index.o: index.c
	$(CC) -c $^ -o $@
request.o: request.c
	$(CC) -c $^ -o $@
header_list_pool.o: header_list_pool.c
	$(CC) -c $^ -o $@
response.o: response.c
	$(CC) -c $^ -o $@
connection.o: connection.c
	$(CC) -c $^ -o $@
alist.o: alist.c
	$(CC) -c $^ -o $@
tslist.o: tslist.c
	$(CC) -c $^ -o $@
http.o: http.c
	$(CC) -c $^ -o $@
tools.o: tools.c
	$(CC) -c $^ -o $@
hpcap_utils.o: hpcap_utils.c
	$(CC) -c $^ -o $@ 
prueba_hpcap: prueba_hpcap.c hpcap_utils.o lib/libmgmon.c
	$(CC) $(LIB_DIR) -o $@ $^ -lhpcap -lpcap -lm -lpthread
httpDissector: httpDissector.c sampling_index.o counters.o index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o NDleeTrazas.o args_parse.o hpcap_utils.o
	$(CC)  -c $(CFLAGS) httpDissector.c -o httpDissector.o
	$(CC)  $(LIB_DIR) $^ -o $@ $(PCAPLIB) $(LDFLAGS)
httpDissector_LOW_MEMORY: httpDissector.c sampling_index.o counters.o index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o NDleeTrazas.o args_parse.o hpcap_utils.o
	$(CC_LOW)  -c $(CFLAGS) httpDissector.c -o httpDissector.o
	$(CC_LOW)  $(LIB_DIR) $^ -o $@ $(PCAPLIB) $(LDFLAGS)
httpDissectorHPCAP: httpDissector.c sampling_index.o counters.o index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o NDleeTrazas.o args_parse.o hpcap_utils.o lib/libmgmon.c
	$(CC_HPCAP)  -c $(CFLAGS) httpDissector.c -o httpDissector.o
	$(CC_HPCAP)  $(HPCAP_DIR) $(LIB_DIR) $^ -o httpDissector $(PCAPLIB) $(HPCAPFLAGS) $(LDFLAGS)
httpDissector_packetFeeder: httpDissector.c sampling_index.o counters.o index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o ../packet_feeder_shrmem/packet_feeder_NDLT.o args_parse.o hpcap_utils.o lib/libmgmon.c ../packet_feeder_shrmem/packet_buffers.o
	$(MAKE) -C $(PACKETFEEDERDIR)
	$(CC)  -c $(CFLAGS) httpDissector.c -o httpDissector.o
	$(CC)  $(LIB_DIR) $^ -o $@ $(PCAPLIB) $(LDFLAGS)
NDleeTrazas.o: NDleeTrazas.c
	$(CC) -std=gnu99 -c NDleeTrazas.c -o NDleeTrazas.o
args_parse.o: args_parse.c
	$(CC) -c $^ -o $@
clean:	
	rm -f *.o prueba_hpcap index counters alist tools tslist args_parse http httpDissector httpDissector_packetFeeder NDleeTrazas list indiceTraza
