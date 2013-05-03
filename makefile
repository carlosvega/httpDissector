CC = gcc -g -O3 -Wall
#CFLAGS		= -g -O2 -D_BSD_SOURCE 
COLOURFLAGS = -D _colours
LDFLAGS		= 

GLIB =  `pkg-config --cflags --libs glib-2.0`  -L/usr/lib 

#PCAP_CFLAGS	= -I/usr/include/pcap
PCAPLIB		= -lpcap

#LNET_CFLAGS	= -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
LNETLIB		= libnet-1.1.6/src/.libs/libnet.a
#-lnet

#LIBS_CFLAGS	=  $(PCAP_CFLAGS) $(LNET_CFLAGS)
LIBS_SRC	= libnids-1.24/src/libnids.a
LIBS		= $(PCAPLIB) $(LNETLIB) -lgthread-2.0 

all: hope

alist.o: alist.c
	$(CC) -c alist.c -o alist.o
tslist.o: tslist.c
	$(CC) -c tslist.c -o tslist.o
http.o: http.c
	$(CC) -c http.c -o http.o
tools.o: tools.c
	$(CC) -c tools.c -o tools.o
hope: hope.c tslist.o tools.o http.o alist.o NDleeTrazas.o args_parse.o
	$(CC) -pthread -c $(CFLAGS) hope.c -o hope.o $(PCAPLIB) $(GLIB)
	$(CC) -pthread hope.o args_parse.o NDleeTrazas.o tslist.o tools.o http.o alist.o  -o hope $(PCAPLIB) $(GLIB)
NDleeTrazas.o: NDleeTrazas.c
	$(CC) -std=gnu99 -c NDleeTrazas.c -o NDleeTrazas.o
args_parse.o: args_parse.c
	$(CC) -c args_parse.c -o args_parse.o
prueba: NDleeTrazas.o args_parse.o
	$(CC) -c prueba.c -o prueba.o
	$(CC) prueba.o args_parse.o NDleeTrazas.o -o prueba $(PCAPLIB)
clean:	
	rm -f *.o tslist alist tools tslist args_parse http hope NDleeTrazas
