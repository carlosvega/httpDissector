#include <worm.h>
#include <worm_private.h>
#include <common.h>
#include <assert.h>

#include <string.h>
#include <stdio.h>
#include "worm_pcap_bridge.h"

NDLTdata_t *NDLTabrirTraza(char *path, char *format, char *filter, int multi, char *errbuf)
{
	UNUSED(path);
	UNUSED(format);
	UNUSED(filter);
	UNUSED(multi);
	UNUSED(errbuf);
	NDLTdata_t *ndlt_data = malloc(sizeof(NDLTdata_t));
	ndlt_data->bytesTotalesLeidos = 0;
	ndlt_data->bytesTotalesFicheros = 0;
	ndlt_data->numPktsLeidos = 0;

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
		callback(user, &pkthdr, bytes);
	}

	return 1;
}

void NDLTclose(NDLTdata_t *ndlt_data)
{
	WH_halt();
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
