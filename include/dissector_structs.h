#ifndef _dissector_structs
#define _dissector_structs

#include "NDleeTrazas.h"
#include <netinet/in.h>
#include <pcap.h>
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <inttypes.h>

#define FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

#define SIZE_ETHERNET 14
#define ADDR_CONST 16
#define AGENT_SIZE 64
#define URL_SIZE 2500
#define HOST_SIZE 256
#define RESP_MSG_SIZE 256

//HASH TABLE 

/*
2^23     8,388,608
2^24    16,777,216
2^25    33,554,432
2^26    67,108,864
2^27   134,217,728
2^28   268,435,456
2^29   536,870,912
2^30 1,073,741,824
*/

#define EVENT_TABLE_SIZE 67108864// 2^26 // 4194304 //2^22
#define COLLISION_SIZE 5//134217728/EVENT_TABLE_SIZE //2^27 / 2^25 = 4 

#define GC_SLEEP_SECS 1000000

typedef enum {ERR = 0, HEAD, GET, POST, PUT, DELETE, TRACE, OPTIONS, CONNECT, PATCH, RESPONSE} http_op;

typedef struct {
  NDLTdata_t *ndldata;
  pcap_t *handle;
  struct timespec last_packet;
  struct timespec first_packet;
  //THREADS
  pthread_mutex_t mutex;
  pthread_t collector;
  pthread_t progress;
  //PACKETS
  u_int32_t packets;
  struct timeval start;
  int running;
  unsigned int nFiles;
  long max_caplen;
  long max_len;
} process_info;

typedef enum {EMPTY = 0, WAITING_REQUEST, WAITING_RESPONSE, TRANSACTION_COMPLETE} http_status;

typedef u_int32_t tcp_seq;

typedef struct {
  unsigned int ip_src;
  unsigned int ip_dst;
  unsigned short port_src;
  unsigned short port_dst;
  tcp_seq ack_seq;
} hash_key;

typedef struct {
  hash_key key;
  char agent[AGENT_SIZE];
  char url[URL_SIZE];
  char host[HOST_SIZE];
  char response_msg[RESP_MSG_SIZE];
  short response_code;
  http_status status; //EMPTY, WAITING_REQUEST, WAITING_RESPONSE, TRANSACTION_COMPLETE
  struct timespec ts_req;
  struct timespec ts_res;
  // struct timespec created_at;
  http_op method;
  unsigned long parent;
} http_event;

typedef struct {
    http_event *events[COLLISION_SIZE];
    // unsigned int size;
    unsigned int used;
    unsigned long parent;
    // unsigned long id;
} collision_list;

//PACKET INFO

typedef struct {
  struct sniff_ethernet *ethernet;// The ethernet header
  struct sniff_ip *ip;            // The IP header
  struct sniff_tcp *tcp;          // The TCP header
  // char ip_addr_src[ADDR_CONST];
  // char ip_addr_dst[ADDR_CONST];
  unsigned int ip_src;
  unsigned int ip_dst;
  struct timespec ts;
  char agent[AGENT_SIZE];
  char url[URL_SIZE];
  char host[HOST_SIZE];
  u_int size_ip;
  u_int size_tcp;
  u_int size_payload;
  u_char *payload;                // Packet payload
  char response_msg[RESP_MSG_SIZE];
  short responseCode;
  unsigned short port_src;
  unsigned short port_dst;
  short request;
  http_op op;
} packet_info;


typedef struct {
  char response_msg[RESP_MSG_SIZE];
  // tcp_seq seq;         // Sequence number
  // tcp_seq ack;         // Acknowledgement number
  struct timespec ts;
  short responseCode;
  http_op op;
} response;

typedef struct __attribute__((packed)) {
  char url[URL_SIZE];
  char host[HOST_SIZE];
  char agent[AGENT_SIZE];
  tcp_seq seq;          // Sequence number
  tcp_seq ack;          // Acknowledgement number
  struct timespec ts;
//NOT USED  response *aux_res;
  http_op op;
} request;

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

      /* Ethernet header */
      struct sniff_ethernet {
              u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
              u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
              u_short ether_type; /* IP? ARP? RARP? etc */
      };

      /* IP header */
      struct sniff_ip {
              u_char ip_vhl;          /* version << 4 | header length >> 2 */
              u_char ip_tos;          /* type of service */
              u_short ip_len;         /* total length */
              u_short ip_id;          /* identification */
              u_short ip_off;         /* fragment offset field */
      #define IP_RF 0x8000            /* reserved fragment flag */
      #define IP_DF 0x4000            /* don't fragment flag */
      #define IP_MF 0x2000            /* more fragments flag */
      #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
              u_char ip_ttl;          /* time to live */
              u_char ip_p;            /* protocol */
              u_short ip_sum;         /* checksum */
              struct in_addr ip_src,ip_dst; /* source and dest address */
      };
      #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
      #define IP_V(ip)                (((ip)->ip_vhl) >> 4)

      /* TCP header */
      struct sniff_tcp {
              u_short th_sport;       /* source port */
              u_short th_dport;       /* destination port */
              tcp_seq th_seq;         /* sequence number */
              tcp_seq th_ack;         /* acknowledgement number */

              u_char th_offx2;        /* data offset, rsvd */
      #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
              u_char th_flags;
      #define TH_FIN 0x01
      #define TH_SYN 0x02
      #define TH_RST 0x04
      #define TH_PUSH 0x08
      #define TH_ACK 0x10
      #define TH_URG 0x20
      #define TH_ECE 0x40
      #define TH_CWR 0x80
      #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
              u_short th_win;         /* window */
              u_short th_sum;         /* checksum */
              u_short th_urp;         /* urgent pointer */
};


#endif
