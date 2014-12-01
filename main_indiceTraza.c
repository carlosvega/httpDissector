
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pcap.h>
#include "NDleeTrazas.h"
//#include "utils.h"

#define INDICETRAZAS_DEFTAMBLOQUEBYTES  0
#define INDICETRAZAS_DEFTAMCLOQUEPKTS   100

//variables globales
static int     showProgress = 0;

struct Parametros {
    NDLTdata_t  *fichTraza;
    unsigned long long  tamBloqueBytes;
    unsigned long long  tamBloquePkts;
};

void printOptions(char *cmd) {
    fprintf(stderr, "Usage: %s -f input_file [-p formato] [-m] [-b tamBloqueBytes] [-k tamBloquePkts] [-t pcap_filter] [-s] [-h]\n", cmd);
    fprintf(stderr, "\t-f input_file : Fichero de traza o fichero de listado de ficheros (controlado por otra opcion)\n");
    fprintf(stderr, "\t-p formato : Formato de traza (%s, %s) {def: pcap}\n", NDLTFORMAT_PCAP_STR, NDLTFORMAT_DRIV_STR);
    fprintf(stderr, "\t-m : Si esta presente quiere decir que en -f se indica un fichero con listado de ficheros, si no esta es que es el unico fichero de traza. Este programa NO funciona en el caso de un fichero con listado de ficheros de más de una interfaz\n");
    fprintf(stderr, "\t-b tamBloqueBytes : Aproximadamente crear un elemento de indice cada este numero de bytes de traza (def: %u)\n", INDICETRAZAS_DEFTAMBLOQUEBYTES);
    fprintf(stderr, "\t-k tamBloquePkts : Crear un elemento de indice cada este numero de paquetes (def: %u)\n", INDICETRAZAS_DEFTAMCLOQUEPKTS);
    fprintf(stderr, "\t-t pcap_filter : aplicar a la traza ese filtro de pcap (poner el filtro entre comillas para que se pase como un solo argumento). Este filtro afecta a todos los resultados que se calculan.\n");
    fprintf(stderr, "\t-s : Muestra progreso por stderr\n");
    fprintf(stderr, "\t-h : ayuda explicando las opciones y el formato de salida\n");
    fprintf(stderr, "Formato de salida: num_paquete num_fichero byte_posicion");
    fprintf(stderr, "\tnum_paquete : numero de paquete al que hace referencia este indice. El primero es el 1 y NO se reinicia el contador al cambiar de fichero en una secuencia de ficheros.\n");
    fprintf(stderr, "\tnum_fichero : numero de fichero en el que se encuentra este paquete. Si solo hay un fichero es el 1. Si hay una secuencia de ficheros el primero es el 1\n");
    fprintf(stderr, "\t byte_posicion : byte del fichero al que hay que desplazarse para leer este paquete\n");
}


void manejaPaquete(u_char *user, const struct NDLTpkthdr *header, const u_char *bytes){
	static unsigned long long pktsLeidos = 1;
	struct Parametros   *params = (struct Parametros*)user;
    int     hayQueVolcarIndice = 0;
    static long long    posUltimoVolcado = 0;
        
    if (NULL == params) {
        fprintf(stderr, "Error interno\n");
        exit(-1);
    }
    
    NDLTdata_t *fichTraza = params->fichTraza;
    if (NULL == fichTraza) {
        fprintf(stderr, "Error en el fichero\n");
        exit(-1);
    }

    if (params->tamBloquePkts > 0) {
        if (pktsLeidos % params->tamBloquePkts == 0) hayQueVolcarIndice = 1;
    }
    if (params->tamBloqueBytes > 0) {
        if ((NDLTbytesRead(fichTraza)-posUltimoVolcado)/params->tamBloqueBytes > 0){
            hayQueVolcarIndice = 1;
            posUltimoVolcado = NDLTbytesRead(fichTraza);
        }
    }
    if (pktsLeidos == 1) hayQueVolcarIndice = 0;
    
    if (hayQueVolcarIndice) {
        int     fileNumber;
        unsigned long long  posPaquete;
        
        fileNumber = NDLTfileNumber(fichTraza);
        posPaquete = NDLTposThisPacket(fichTraza);
        
        fprintf(stdout, "%llu %u %llu %ld.%09ld\n", pktsLeidos, fileNumber, posPaquete, header->ts.tv_sec, header->ts.tv_nsec);
    }
    
    pktsLeidos++;

}


int main (int argc, char **argv) {
    char    *fileFormat = "pcap";
    char    *pcapFilePath = NULL;
    int     multiplesFicheros = 0;
    char    *pcapFilter = NULL;
    unsigned long long  tamBloqueBytes = INDICETRAZAS_DEFTAMBLOQUEBYTES;
    unsigned long long  tamBloquePkts = INDICETRAZAS_DEFTAMCLOQUEPKTS;
	char    option;
    NDLTdata_t *fichTraza;
    char errbuf[PCAP_ERRBUF_SIZE];
    int     resLoop;
    struct Parametros   params;

	if(argc<2){
		printf("Faltan parametros\n\n");
		printOptions(argv[0]);
		exit(0);
	}
	while ((option = getopt(argc, argv, "f:p:t:b:k:msh")) != -1) {
		switch (option) {
			case 'h':
				printOptions(argv[0]);
				exit(0);
				break;
			case 'p':
				fileFormat=optarg;
				break;
			case 'f':
				pcapFilePath = optarg;
				break;
            case 'b':
 				if (optarg == NULL) {
                    fprintf(stderr, "Falta el parametro de la opcion -b");
                    exit(-1);
                }
                tamBloqueBytes = atoll(optarg);
                break;
            case 'k':
 				if (optarg == NULL) {
                    fprintf(stderr, "Falta el parametro de la opcion -k");
                    exit(-1);
                }
                tamBloquePkts = atoll(optarg);
                break;
            case 't':
				if (optarg == NULL) {
                    fprintf(stderr, "Falta el parametro de la opcion -t");
                    exit(-1);
                }
                pcapFilter = optarg;
                break;
			case 'm':
                multiplesFicheros = 1;
                break;
            case 's':
                showProgress = 1;
                break;
		}
	}

	fichTraza = NDLTabrirTraza(pcapFilePath, fileFormat, pcapFilter, multiplesFicheros, errbuf);
    if (NULL == fichTraza) {
        fprintf(stderr, "Error abriendo la traza: %s\n", errbuf);
        exit(-1);
    }
    
    params.fichTraza = fichTraza;
    params.tamBloqueBytes = tamBloqueBytes;
    params.tamBloquePkts = tamBloquePkts;
    
    resLoop = NDLTloop(fichTraza, manejaPaquete, (u_char*)&params);
    if (resLoop!=1) {
        fprintf(stderr, "Error en NDLTloop ");
    }
    return resLoop;
}

