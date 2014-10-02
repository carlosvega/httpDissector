CC = gcc -O3 -Wall -Iinclude/ $(DEBUG)
LDFLAGS = -lm -lpthread
#CFLAGS		= -g -O3 -D_BSD_SOURCE 
COLOURFLAGS = -D _colours

#GLIB =  `pkg-config --cflags --libs glib-2.0`  -L/usr/lib 

#GOBJECT = `pkg-config --cflags gobject-2.0`

-DG_DISABLE_DEPRECATED=1

GLIBs   = `pkg-config  --libs glib-2.0`
GLIBcf  = `pkg-config  --cflags glib-2.0`

GTHREAD = `pkg-config --libs gthread-2.0`
GTHREADcf = `pkg-config --cflags gthread-2.0`

GLIBcflags = $(GLIBcf) $(GTHREADcf)
GLIBlink = -L /usr/lib/ $(GLIBs) $(GTHREAD)

#PCAP_CFLAGS	= -I/usr/include/pcap
PCAPLIB		= -lpcap

#LNET_CFLAGS	= -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
LNETLIB		= libnet-1.1.6/src/.libs/libnet.a
#-lnet

#LIBS_CFLAGS	=  $(PCAP_CFLAGS) $(LNET_CFLAGS)
LIBS_SRC	= libnids-1.24/src/libnids.a
LIBS		= $(PCAPLIB) $(LNETLIB) -lgthread-2.0 

all: httpDissector

err_mqueue: err_mqueue.c
	$(CC) -c -lpthread err_mqueue.c -o err_mqueue.o
sampling_index.o: sampling_index.c
	$(CC) -c sampling_index.c -o sampling_index.o
list.o: list.c
	$(CC) -c list.c -o list.o
sorted_print.o: sorted_print.c
	$(CC) -c sorted_print.c -o sorted_print.o
IPflow.o: IPflow.c
	$(CC) -c IPflow.c -o IPflow.o
counters.o: counters.c
	$(CC) -c counters.c -o counters.o
index.o: index.c
	$(CC) -c index.c -o index.o
request.o: request.c
	$(CC) -c request.c -o request.o
header_list_pool.o: header_list_pool.c
	$(CC) -c header_list_pool.c -o header_list_pool.o
response.o: response.c
	$(CC) -c response.c -o response.o
connection.o: connection.c
	$(CC) -c connection.c -o connection.o
alist.o: alist.c
	$(CC) -c alist.c -o alist.o
tslist.o: tslist.c
	$(CC) -c tslist.c -o tslist.o
http.o: http.c
	$(CC) -c http.c -o http.o
tools.o: tools.c
	$(CC) -c tools.c -o tools.o
httpDissector: httpDissector.c sampling_index.o counters.o  index.o connection.o sorted_print.o list.o request.o response.o tools.o http.o alist.o NDleeTrazas.o args_parse.o
	$(CC)  -c $(CFLAGS) httpDissector.c -o httpDissector.o
	$(CC)  httpDissector.o counters.o sampling_index.o index.o connection.o sorted_print.o list.o request.o response.o args_parse.o NDleeTrazas.o tools.o http.o alist.o -o httpDissector $(PCAPLIB) $(LDFLAGS)
NDleeTrazas.o: NDleeTrazas.c
	$(CC) -std=gnu99 -c NDleeTrazas.c -o NDleeTrazas.o
args_parse.o: args_parse.c
	$(CC) -c args_parse.c -o args_parse.o
prueba: NDleeTrazas.o args_parse.o
	$(CC) -c prueba.c -o prueba.o
	$(CC) prueba.o args_parse.o NDleeTrazas.o -o prueba $(PCAPLIB)
clean:	
	rm -f *.o index counters alist tools tslist args_parse http httpDissector NDleeTrazas list
