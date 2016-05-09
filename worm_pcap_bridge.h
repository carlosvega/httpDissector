#ifndef _WORM_PCAP_BRIDGE_H_
#define _WORM_PCAP_BRIDGE_H_

#include <stdint.h>
#include <stdio.h>
#include <pcap.h>

struct NDLTpkthdr {
    struct timespec ts;
    unsigned int    caplen;
    unsigned int   len;
};

typedef struct {
	unsigned long long start_packet;
	unsigned long long start_ts;
	unsigned long long start_byte;

	unsigned long long end_packet;
	unsigned long long end_ts;
	unsigned long long end_byte;
} interval;

typedef void (*packet_handler)(u_char *user, const struct NDLTpkthdr *h, const u_char *bytes);

struct NDLTdata {
	char filename[10000];
	char current_filename[10000];
	unsigned char buffer[10000];
	int fd;
	FILE *multi_fd;
	size_t position;
	unsigned char *packet_buffer;
	int end_of_file;
	int wait_read_counter;
	char *pcapFilterString; // cadena con filtro pcap a aplicar
	struct bpf_program  *filtroPcapCompilado; // filtro compilado
	int contFiles;
	size_t bytesTotalesLeidos;
	size_t bytesTotalesFicheros;
	size_t numPktsLeidos;
	int multi;
	size_t acks;
	interval *index_intervals;
	unsigned long number_of_intervals;
};
typedef struct NDLTdata NDLTdata_t;

NDLTdata_t *NDLTabrirTraza(char *path, char *format, char *filter, int multi, char *errbuf);
int NDLTnext_ex(NDLTdata_t *ndlt_data, struct NDLTpkthdr **pkthdr, unsigned char **pkt_data);
int NDLTloop(NDLTdata_t *ndlt_data, packet_handler callback, unsigned char *user);
void NDLTclose(NDLTdata_t *ndlt_data);
int NDLTopenFileDiscards(NDLTdata_t *trazas,char *pathFile,char *errbuf);
unsigned long long NDLTpktNumber(NDLTdata_t *trazas);
int NDLTsetIndexFile(NDLTdata_t *trazas, char *indexFilePath);
FILE *NDLTfile(NDLTdata_t *trazas);
int NDLTjumpToPacket(NDLTdata_t *trazas, unsigned long long pktNumber);
int NDLTcompile(int snaplen_arg, int linktype_arg, struct bpf_program *program, const char *buf, int optimize, bpf_u_int32 mask);
int NDLTfilter(struct bpf_program *fp, const struct NDLTpkthdr *h, const u_char *pkt);
void NDLTfreecode(struct bpf_program *fp);

#endif
