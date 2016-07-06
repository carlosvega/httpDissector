#include <worm.h>
#include <worm_private.h>
#include <common.h>
#include <assert.h>

#include <string.h>
#include <stdio.h>
#include <pcap.h>

#include "worm_pcap_bridge.h"

#define CAPLEN 		65535

NDLTdata_t *NDLTabrirTraza(char *path, char *format, char *filter, int multi, char *errbuf)
{
	UNUSED(path);
	UNUSED(format);
	UNUSED(multi);
	UNUSED(errbuf);
	NDLTdata_t *ndlt_data = calloc(sizeof(NDLTdata_t), 1);
	ndlt_data->bytesTotalesLeidos = 0;
	ndlt_data->bytesTotalesFicheros = 0;
	ndlt_data->numPktsLeidos = 0;

	if (filter) {
		ndlt_data->filtroPcapCompilado = calloc(sizeof(struct bpf_program), 1);
		if (!ndlt_data->filtroPcapCompilado) {
			return 0;
		}
		if (NDLTcompile(CAPLEN, DLT_EN10MB, ndlt_data->filtroPcapCompilado, filter, 1, 0)) {
			if (errbuf) {
				sprintf(errbuf, "Error: no se pudo compilar el filtro %s", filter);
			}

			return 0;
		}
	} else {
		ndlt_data->filtroPcapCompilado = 0;
	}

	int st = WH_init();
	assert(st == 0);

	return ndlt_data;
}

int NDLTnext_ex(NDLTdata_t *ndlt_data, struct NDLTpkthdr **pkthdr, unsigned char **pkt_data)
{
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t incl_len;
	uint32_t orig_len;

	MessageInfo mi;
	mi.size = 10000 + sizeof(uint32_t) * 4;
	mi.type = 0;

	int recvret = WH_recv((void *)(ndlt_data->buffer), &mi);

	if (!recvret) {
		return 0;
	}

	ts_sec = *((uint32_t *)((ndlt_data->buffer) + 0));
	ts_usec = *((uint32_t *)((ndlt_data->buffer) + 4));
	incl_len = *((uint32_t *)((ndlt_data->buffer) + 8));
	orig_len = *((uint32_t *)((ndlt_data->buffer) + 12));

	(*pkthdr)->ts.tv_sec = ts_sec;
	(*pkthdr)->ts.tv_nsec = ts_usec * 1000;
	(*pkthdr)->len = orig_len;
	(*pkthdr)->caplen = incl_len;

	*pkt_data = (ndlt_data->buffer) + sizeof(uint32_t) * 4;

	ndlt_data->bytesTotalesLeidos += (*pkthdr)->caplen;
	ndlt_data->bytesTotalesFicheros += (*pkthdr)->caplen;
	++(ndlt_data->numPktsLeidos);

	return 1;
}

int NDLTloop(NDLTdata_t *ndlt_data, packet_handler callback, unsigned char *user)
{
	struct NDLTpkthdr pkthdr;
	struct NDLTpkthdr *pkthdr_ptr = &pkthdr;
	unsigned char *bytes;

	while (NDLTnext_ex(ndlt_data, &pkthdr_ptr, &bytes)) {
		if (ndlt_data->filtroPcapCompilado) {
			if (NDLTfilter(ndlt_data->filtroPcapCompilado, &pkthdr, bytes)) {
				callback(user, &pkthdr, bytes);
			}
		} else {
			callback(user, &pkthdr, bytes);
		}
	}

	return 1;
}

void NDLTclose(NDLTdata_t *ndlt_data)
{
	WH_halt();
	NDLTfreecode(ndlt_data->filtroPcapCompilado);
	free(ndlt_data);
}

int NDLTopenFileDiscards(NDLTdata_t *trazas, char *pathFile, char *errbuf)
{
	UNUSED(trazas);
	UNUSED(pathFile);
	UNUSED(errbuf);
	//TODO
	return 1;
}

unsigned long long NDLTpktNumber(NDLTdata_t *trazas)
{
	return (unsigned long long) trazas->numPktsLeidos;
}

int NDLTsetIndexFile(NDLTdata_t *trazas, char *indexFilePath)
{
	UNUSED(trazas);
	UNUSED(indexFilePath);
	//TODO?
	return 1;
}

FILE *NDLTfile(NDLTdata_t *trazas)
{
	UNUSED(trazas);
	//TODO?
	return 0;
}

int NDLTjumpToPacket(NDLTdata_t *trazas, unsigned long long pktNumber)
{
	UNUSED(trazas);
	UNUSED(pktNumber);
	//TODO?
	return 1;
}

/*
 * Función que compila un filtro BPF. Es un wrapper para pcap_compile_nopcap. Tiene unos requerimientos especiales (el resto de parámetros, igual que en pcap_compile). Se usa para poder filtrar por 'n' filtros, ya que NDLTloop solo permite filtrar por uno solo:
 *
 * - snaplen: si es una captura en RAW, hay que saber qué snaplen se ha puesto y meterlo a mano.
 * - linktype: lo mismo. Se pueden utilizar los de PCAP (DLT_<algo>). Ej: DLT_EN10MB para ethernet.
 *
 *  Devuelve 0 si no hay error.
 */
int NDLTcompile(int snaplen_arg, int linktype_arg, struct bpf_program *program, const char *buf, int optimize, bpf_u_int32 mask)
{
	return pcap_compile_nopcap(snaplen_arg, linktype_arg, program, (char *)buf, optimize, mask);
}

// Dado un paquete, se aplica el filtro BPF. Devuelve 0 si el paquete no pasa el filtro y distinto de 0 en caso contrario.
int NDLTfilter(struct bpf_program *fp, const struct NDLTpkthdr *h, const u_char *pkt)
{
	struct bpf_insn *fcode = fp->bf_insns;

	if (fcode != NULL) {
		return (bpf_filter(fcode, (u_char *)pkt, h->len, h->caplen));

	} else {
		return (0);
	}
}

// Wrapper para pcap_freecode. Libera memoria de un filtro BPF.
void NDLTfreecode(struct bpf_program *fp)
{
	pcap_freecode(fp);
	return;
}
