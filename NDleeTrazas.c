//
//  NDleeTrazas.c
//  
//
//

#include "NDleeTrazas.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pcap.h>
#include <dirent.h>



#define NDLTFORMAT_PCAP    1
#define NDLTFORMAT_DRIV    2


// #define TAM_LINE 	1000
//#define MAX_PACKET_LEN 	2048
// #define MAX_PACKET_LEN 	65535
#define CAPLEN 		65535

#define BLOQUE_INDICES	1000     // Cantidad de indices a reservar cada vez

//#define NUM_FICH_INTERFACE 3000   //Cantidad de ficheros que puede haber por interfaz

// union descriptores 
// {
// 	FILE 		*fh;    //file handle  (usado para abrir el fichero raw para leer o escribir la traza)
// 	pcap_t 		*ph;    //pcap handle  (usado para abrir el pcap para leer la traza)
// 	pcap_dumper_t 	*pdh;   //pcap dump handler (usado para abrir el pcap en escritura)
// };

// Elemento de indice
struct NDLTindexElement {
	int     		fileIndex;  	// Numero de fichero. Cuando hay uno solo vale 0. Si hay multiples entonces el primero es el 0
	unsigned long long	numPacket;  	// Numero de paquete, contando desde el comienzo de toda la traza (o multiples ficheros)
	unsigned long long	bytesPosition;  // Byte en este fichero en el que empieza ese paquete
};

//una union para guardar el paquete según el tipo de traza que sea
union contenidoPaquete{
	u_char buffer[MAX_PACKET_LEN];  	//para el tipo raw
	const u_char *pkt; 			//para el tipo pcap
};

//Esta estructura guarda información sobre una interfaz.
struct interfaces_t{
	//char ficheros[NUM_FICH_INTERFACE][TAM_LINE];	// array con el nombre de los ficheros de trazas de la interfaz
	char **ficheros;				// array con el nombre de los ficheros de trazas de la interfaz
	int numFicheros;				// contador de ficheros
	union descriptores 	trazaAbierta;		// va a contener el descriptor de fichero que está abierto en ese momento
	int numficheroParaAbrir;  			// numero de indice que indica el fichero que toca abrir en ese momento 
	struct NDLTpkthdr pkthdr;			// contiene el header del paquete que se ha leido del fichero abierto
	union contenidoPaquete packet;			// contiene los datos del paquete que se ha leido del fichero abierto
	int leidosTodos;				// flag que indica si ya se han leido todos los ficheros del array 'ficheros'
	unsigned long long posThisPacket;		// posición en bytes en el fichero actual del comienzo del paquete que se acaba de leer. Es diferente de la posición de lectura en el fichero, que sería la del siguiente paquete
	unsigned long long posALeerDeFichero;		// posicion en la que se queda el fichero después de leer un paquete
};

// struct NDLTdata{
// 	char                path[TAM_LINE];  		// nombre del fichero de trazas, o del fichero de paths de trazas
// 	FILE                *fileOfPaths;		// fichero de paths
// 	int                 fileFormato;  		// NDLTFORMAT_PCAP si la traza es pcap, NDLTFORMAT_DRIV si la traza es raw
// 	int                 multiFile; 			// 1 si se trata de múltiples ficheros, 0 en caso contrario
// 	char                *pcapFilterString;		// cadena con filtro pcap a aplicar
// 	struct bpf_program  filtroPcapCompilado; 	// filtro compilado
// 	union descriptores  traceFile;              	// fichero de traza abierto
// 	int                 contFiles;  		// contador que indica el número de fichero en el que se está, empezando en 1. (En el caso de que se pase el fichero de trazas este contador será 1 en cuanto se empiece a leer).
// 	unsigned long long  bytesTotalesLeidos;     	// Numero total de bytes leidos entre todos los ficheros de la traza
// 	unsigned long long  bytesTotalesFicheros;	// numero total de bytes de los ficheros
	
// 	unsigned long long  posThisPacket;          	// posición en bytes en el fichero actual del comienzo del paquete que se acaba de leer. Es diferente de la posición de lectura en el fichero, que sería la del siguiente paquete
// 	FILE                *fileIndex;             	// Fichero con indices
// 	int                 maxIndicesCreados;      	// Número máximo de indices para los que hay reservada memoria en indices
// 	int                 numIndicesLeidos;       	// Cantidad de elementos que hay usados en indices
// 	struct NDLTindexElement *indices;           	// Array de elementos de indice
// 	int                 shouldBreakLoopFlag;    	// Lo pone a 1 NDLTbreakloop() para avisar a NDLTloop() que debe terminar
// 	 unsigned long long  numPktsLeidos;          	// Numero de paquetes leidos hasta el momento en toda la traza
	
// 	int		    jumpPacketActivated;  	// Si está a 1 indica que se ha pedido saltar a un paquete en concreto. 
// 	unsigned long long  numPacketsDiscarded;	// número de paquetes descartados hasta el momento (tanto por paquetes descartados como por paquetes que no pasen el filtro)
// 	unsigned long long  nextPacketToDiscard; 	//numero del siguiente paquete a descartar (se van leyendo del fichero de paquetes a descartar)
// 	FILE 		*filePacketsToDiscard;		// handle del fichero con los paquetes a descartar (paquetes duplicados)
// 	//int		errorToStdErr;			// Flag que si es 1 los errores de NDLTloop se vuelvan por stderr, y si es 0 no se vuelvan. 
// 	FILE		*fileForError;			// Apuntador de fichero donde irán los errores. Por defecto está a stderr
	
// 	struct interfaces_t 	*interfaces; 		// array de estructuras 'struct interfaces_t' (una estructura para cada interfaz que haya en el fichero de entrada. Las interfaces vienen separadas por una línea en blanco)
// 	int 			numInterfaces;		// contador de interfaces
	
// 	int			nextPacketActive;  //Si se ha llamado a la función NDLTnext().
// 	struct NDLTpkthdr 	pkthdr_next;		//header a devolver si se llama a NDLTnext()
// 	u_char			packet_next[MAX_PACKET_LEN];		//paquete a devolver si se llama a NDLTnext()
// 	//unsigned int 		tamPacket;
	
// };

struct NDLTdataEscritura{
	char    		path[TAM_LINE];
	union descriptores  	traceFile;		// fichero de traza abierto			
	int     		fileFormato;  		// NDLTFORMAT_PCAP si el fichero de salida es pcap, NDLTFORMAT_DRIV si es raw	
	int 			displayOutput;		// 1 si se muestran los paquetes por pantalla. 0 si se guardan a archivo 
	unsigned int		snaplen;		// bytes que se quieren sacar del paquete.
};

//estructura para leer la cabecera de un paquete raw del fichero
typedef struct{
	u_int32_t	secs;
	u_int32_t	nsecs;
	u_int16_t	caplen;
	u_int16_t	len;
} header_RAW_t;


/*
 * Función que compila un filtro BPF. Es un wrapper para pcap_compile_nopcap. Tiene unos requerimientos especiales (el resto de parámetros, igual que en pcap_compile). Se usa para poder filtrar por 'n' filtros, ya que NDLTloop solo permite filtrar por uno solo:
 * 
 * - snaplen: si es una captura en RAW, hay que saber qué snaplen se ha puesto y meterlo a mano.
 * - linktype: lo mismo. Se pueden utilizar los de PCAP (DLT_<algo>). Ej: DLT_EN10MB para ethernet.
 * 
 *  Devuelve 0 si no hay error.
 */
 int NDLTcompile(int snaplen_arg, int linktype_arg, struct bpf_program *program, const char *buf, int optimize, bpf_u_int32 mask) {
	return pcap_compile_nopcap(snaplen_arg, linktype_arg, program, (char*)buf, optimize, mask);
}

// Dado un paquete, se aplica el filtro BPF. Devuelve 0 si el paquete no pasa el filtro y distinto de 0 en caso contrario.
int NDLTfilter(struct bpf_program *fp, const struct NDLTpkthdr *h, const u_char *pkt) {
	struct bpf_insn *fcode = fp->bf_insns;

	if (fcode != NULL) 
		return (bpf_filter(fcode, (u_char*)pkt, h->len, h->caplen));
	else
		return (0);
}

// Wrapper para pcap_freecode. Libera memoria de un filtro BPF.
void NDLTfreecode(struct bpf_program *fp) {
	pcap_freecode(fp);
	return;
}

// Función interna que cierra el último fichero de traza
static void NDLTclose_last(NDLTdata_t *data) {
	if(data->interfaces!=NULL){
		for(int i=0;i<data->numInterfaces;i++){
			if (data->fileFormato==NDLTFORMAT_PCAP){ //si la traza es pcap
				//pcap_close((data->traceFile.ph));
				if(data->interfaces[i].trazaAbierta.ph!=NULL) pcap_close((data->interfaces[i].trazaAbierta.ph));
			} else{
				//fclose(data->traceFile.fh);
				if(data->interfaces[i].trazaAbierta.fh) fclose(data->interfaces[i].trazaAbierta.fh);
			}
			//liberar memoria del array de ficheros
			for(int j=0;j<data->interfaces[i].numFicheros;j++){
				free(data->interfaces[i].ficheros[j]);
			}
			free(data->interfaces[i].ficheros);
		}
	}else{
		if (data->fileFormato==NDLTFORMAT_PCAP){ //si la traza es pcap
			if( data->traceFile.ph!=NULL){
				pcap_close((data->traceFile.ph));
			}	
		} 
		else{
			if( data->traceFile.ph!=NULL){
				fclose(data->traceFile.fh);
			}	
		}
	}
	if (data->pcapFilterString) NDLTfreecode(&data->filtroPcapCompilado);
}

/*
Función interna que lee y abre el siguiente path del fichero de ficheros. Devuelve 1 si exito, 0 si error

*/
static int NDLTopen_next(NDLTdata_t *data, char *errbuf) {
	if (data->multiFile) {
		if (!feof(data->fileOfPaths)) {
			char aux[TAM_LINE];
			if(fgets(aux, TAM_LINE, data->fileOfPaths)==NULL) return 0;
			if (sscanf(aux, "%s", data->path)!=1) {
				if (errbuf) sprintf(errbuf, "Error: no se pudo leer la siguiente línea del fichero");
				return 0;
			}
		} else return 0;
		if (data->contFiles) NDLTclose_last(data);
	} else {
		if (data->traceFile.fh || data->traceFile.ph) return 0;
	}
	if (data->fileFormato == NDLTFORMAT_PCAP) {
		pcap_t *pcap = pcap_open_offline(data->path, errbuf);
		if (!pcap) {
			if (errbuf) sprintf(errbuf, "Error: no se pudo abrir el fichero %s", data->path);
			return 0;
		}
		data->traceFile.ph = pcap;
	}
	else if (data->fileFormato == NDLTFORMAT_DRIV){
		data->traceFile.fh = fopen(data->path, "r");
		if ((!data->traceFile.fh)&&(errbuf)) sprintf(errbuf, "Error: no se pudo abrir el fichero %s", data->path);
	}
	
	if (data->pcapFilterString){  //si hay un filtro
		if (NDLTcompile(CAPLEN, DLT_EN10MB, &data->filtroPcapCompilado, data->pcapFilterString, 1, 0)) {
			if (errbuf) sprintf(errbuf, "Error: no se pudo compilar el filtro %s", data->pcapFilterString);
			return 0;
		}
	}
	data->contFiles++;
	return 1;
}

/*
Funcion interna que comprueba si un numero de paquete aparece en el fichero de paquetes a descartar. 
Valor devuelto:
	1 indica que si está el paquete en los descartados. 
	0 que no está
	-1 si hay error, que el fichero de descartes no esté ordenado.
*/
static int checkPacketInFile(NDLTdata_t *trazas){
	char aux[TAM_LINE];
	static long long    numLinea=1;
	
	if (!trazas->filePacketsToDiscard) return 0; // Si no hay fichero de descartes devolvemos siempre como si el paquete no hubiera que descartarlo
	if(trazas->nextPacketToDiscard==trazas->numPktsLeidos){
		//se descarta el paquete y se lee el siguiente paquete a descartar
		if(!feof(trazas->filePacketsToDiscard)){
			if (fgets(aux, TAM_LINE, trazas->filePacketsToDiscard)==NULL) {
				fprintf(trazas->fileForError, "Terminado el fichero de paquetes a descartar: %llu lineas\n", numLinea);
				return 1;
			}
			if(trazas->nextPacketToDiscard>=atoll(aux)){
				fprintf(trazas->fileForError, "Error: el fichero con los paquetes a descartar no está ordenado, linea %llu\n", numLinea);
				return -1;
			}
			trazas->nextPacketToDiscard=atoll(aux);
		}
		numLinea++;
		return 1;
	}
	return 0;
}

/*
Lee un paquete de un archivo (formato raw) del interfaz que indique el el parámetro 'indice'
Codigos de resultado:
	- Si es -1 hay un error: el fichero con los paquetes a descartar está desordenado.
	- Si es 0 hay algún error (o bien el caplen es demasiado grande o se ha producido un error al leer el paquete) y se saldrá del programa
	- Si es 1 significa que hemos llegado al pseudo paquete del final del fichero (segundos y nanosegundos son 0) y se tiene que cerrar el fichero
	- Si es 2 hay éxito o se ha terminado el fichero
*/
static int leerPaqueteFile(NDLTdata_t *trazas,int indice){
	header_RAW_t headRaw;
	if(fread(&headRaw,1,sizeof(header_RAW_t),trazas->interfaces[indice].trazaAbierta.fh)!=sizeof(header_RAW_t) ){
		if(feof(trazas->interfaces[indice].trazaAbierta.fh)) return 2;
		
		fprintf(trazas->fileForError, "Error al leer la cabecera del paquete del fichero %s del interfaz %d - Posicion: %llu\n", trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1], (indice-1),(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
		return 0;
	}
	if( (headRaw.secs==0) && (headRaw.nsecs==0)){ 
		// pseudo paquete del final. Saltarlo y cerrar el fichero
		return 1;
	}
	
	//if( headRaw.caplen > MAX_PACKET_LEN ){
	if( headRaw.caplen > headRaw.len ){
		//fprintf(trazas->fileForError, "La longitud del paquete (%d) supera los limites (%d). En el fichero %s - Posicion: %llu \n", headRaw.caplen, MAX_PACKET_LEN,trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1],(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
		fprintf(trazas->fileForError, "El caplen del paquete (%d) supera la longitud, len,  del paquete (%d). En el fichero %s - Posicion: %llu \n", headRaw.caplen, headRaw.len,trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1],(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
		return 0;
	}
	
	if( headRaw.caplen > 0 ){
		//rellenar el NDLTpkthdr
		trazas->interfaces[indice].pkthdr.caplen=headRaw.caplen;
		trazas->interfaces[indice].pkthdr.len=headRaw.len;
		trazas->interfaces[indice].pkthdr.ts.tv_sec=headRaw.secs;
		trazas->interfaces[indice].pkthdr.ts.tv_nsec=headRaw.nsecs;
		
		// leer el paquete
		if (fread(trazas->interfaces[indice].packet.buffer, 1, headRaw.caplen, trazas->interfaces[indice].trazaAbierta.fh) != headRaw.caplen) {
			fprintf(trazas->fileForError, "Error leyendo %u bytes. En el fichero %s - Posicion: %llu\n", headRaw.caplen,trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1],(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
                        return 0;
		}
	} else{ 
		fprintf(trazas->fileForError, "Warning: caplen=0 !! En el fichero %s - Posicion: %llu\n",trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1],(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
		trazas->numPacketsDiscarded++;    
		
		if(trazas->filePacketsToDiscard!=NULL && checkPacketInFile(trazas)==-1) return(-1);
		return 0;
	}
	return 2;
}

//lee un paquete pcap del interfaz que indique el parámetro 'indice'. Devuelve 1 si hay exito o 0 su se ha producido algún error al leer el siguiente paquete pcap, por ejemplo que se haya acabado el fichero.
static int leerPaquetePcap(NDLTdata_t *trazas,int indice){
	struct pcap_pkthdr *hdr;
	if(pcap_next_ex(trazas->interfaces[indice].trazaAbierta.ph, &hdr, &trazas->interfaces[indice].packet.pkt)!=-2){
		//adaptar el struct pcap_pkthdr a un NDLTpkthdr
		trazas->interfaces[indice].pkthdr.caplen=hdr->caplen;
		if(hdr->caplen>MAX_PACKET_LEN ){
			fprintf(trazas->fileForError, "La longitud del paquete (%d) supera los limites (%d). En el fichero %s - Posicion: %llu \n", hdr->caplen, MAX_PACKET_LEN,trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1],NDLTposThisPacket(trazas));
			return 0;
		}
		trazas->interfaces[indice].pkthdr.len=hdr->len;
		trazas->interfaces[indice].pkthdr.ts.tv_sec=hdr->ts.tv_sec;
		trazas->interfaces[indice].pkthdr.ts.tv_nsec=hdr->ts.tv_usec*1000;
		return 1;
	}else return 0;
}

/*
Función que abre el primer fichero de todas las interfaces o el fichero si se trata de una traza directamente.
Devuelve 1 en caso de éxito y 0 en caso de error (que no se pueda abrir algún fichero o haya fichero de descartes que no sea estrictamente creciente)
*/
static int NDLTopen_next_multiple(NDLTdata_t *data, char *errbuf) {
	if (data == NULL) return 0;
	char errbufPcap[PCAP_ERRBUF_SIZE];
	if (data->multiFile) {
		//abrimos el primer fichero de cada interfaz
		for(int i=0;i<data->numInterfaces;i++){
			if (data->fileFormato == NDLTFORMAT_PCAP) {
				data->interfaces[i].trazaAbierta.ph = pcap_open_offline(data->interfaces[i].ficheros[data->interfaces[i].numficheroParaAbrir], errbufPcap);
				if(!data->interfaces[i].trazaAbierta.ph){
					if (errbuf) sprintf(errbuf, "Error al abrir el fichero %s - %s\n", data->interfaces[i].ficheros[data->interfaces[i].numficheroParaAbrir],errbufPcap);
					return 0;
				}
				//leer primer paquete de cada fichero y guardalo
				leerPaquetePcap(data,i);
			}
			else if (data->fileFormato == NDLTFORMAT_DRIV){
				if (data->interfaces == NULL) return 0;
				data->interfaces[i].trazaAbierta.fh=fopen(data->interfaces[i].ficheros[data->interfaces[i].numficheroParaAbrir],"r");
				if(!data->interfaces[i].trazaAbierta.fh && errbuf){ 
					sprintf(errbuf, "Error: no se pudo abrir el fichero %s", data->interfaces[i].ficheros[data->interfaces[i].numficheroParaAbrir]);
					return 0;
				}
				
				int retLeerPaquete = leerPaqueteFile(data, i);
				if(retLeerPaquete==0 || retLeerPaquete==-1) return 0;
			}
			data->interfaces[i].numficheroParaAbrir++;
		}
	}else{
		//abro el fichero con la traza
		if (data->fileFormato == NDLTFORMAT_PCAP) {
			data->traceFile.ph = pcap_open_offline(data->path, errbufPcap);
			if (!data->traceFile.ph) {
				if (errbuf) sprintf(errbuf, "Error al abrir el fichero %s - %s\n", data->path,errbufPcap);
				return 0;
			}
		}
		else if (data->fileFormato == NDLTFORMAT_DRIV){
			data->traceFile.fh = fopen(data->path, "r");
			if ((!data->traceFile.fh)&&(errbuf)){ 
				sprintf(errbuf, "Error: no se pudo abrir el fichero %s", data->path);
				return 0;
			}
		}
	}
	if (data->pcapFilterString){  //si hay un filtro
		if (NDLTcompile(CAPLEN, DLT_EN10MB, &data->filtroPcapCompilado, data->pcapFilterString, 1, 0)) {
			if (errbuf) sprintf(errbuf, "Error: no se pudo compilar el filtro %s", data->pcapFilterString);
			return 0;
		}
	}
	data->contFiles++;  // Que hacer cuando hay mas de un interfaz??
	return 1;
}


/*
Función que comprueba que los parámetros sean correctos y crea una estructura NDLTdata_t con esos parámetros.
Devuelve la estructura NDLTdata_t creada o NULL en caso de error
*/
NDLTdata_t *NDLTabrirTraza(char *path, char *format, char *filter, int multi, char *errbuf) {
	if (!path) {
		if (errbuf) sprintf(errbuf, "Error: especifique una ruta a un fichero");
		return NULL;
	}
	FILE *fileOfPaths = NULL;
	if (multi) {
		fileOfPaths = fopen(path, "r");
		if (!fileOfPaths) {
			if (errbuf) sprintf(errbuf, "Error: no se pudo abrir el fichero");
			return NULL;
		}
	}

	int formato;
	if (!format || strcmp(format, NDLTFORMAT_PCAP_STR) == 0) formato = NDLTFORMAT_PCAP;
	else if (strcmp(format, NDLTFORMAT_DRIV_STR) == 0) formato = NDLTFORMAT_DRIV;
	else {
		if (errbuf) sprintf(errbuf, "Error: formato de traza inválido");
		return NULL;
	}
	
	NDLTdata_t *nuevo = calloc(1,sizeof(NDLTdata_t));
	if (!nuevo) {
		if (errbuf) sprintf(errbuf, "Error creando objeto de tipo NDLTdata_t");
		return NULL;
	}
	
	strncpy(nuevo->path, path, TAM_LINE);
	nuevo->pcapFilterString = filter;
	nuevo->fileFormato = formato;
	nuevo->contFiles = 0;
	nuevo->multiFile = multi;
	nuevo->fileOfPaths = fileOfPaths;
	nuevo->bytesTotalesLeidos = 0;
	nuevo->posThisPacket = 0;
	nuevo->fileIndex = NULL;
	nuevo->numIndicesLeidos = 0;
	nuevo->maxIndicesCreados = 0;
	nuevo->indices = NULL;
	nuevo->numPktsLeidos = 0;
    
	//paquetes a descartar
	nuevo->jumpPacketActivated=0;
	nuevo->numPacketsDiscarded=0;
	nuevo->nextPacketToDiscard=0;
	nuevo->filePacketsToDiscard=NULL;
	
	//nuevo->errorToStdErr=1;  // por defecto, los mensajes de error se vuelcan a stderr.
	nuevo->fileForError=stderr;  // por defecto, los mensajes de error se vuelcan a stderr.
	nuevo->bytesTotalesFicheros=0;
	nuevo->interfaces=NULL;
	
	nuevo->nextPacketActive=0;
	
	struct stat buf;
	//Si el fichero es un file of files se van a guardar los paths de los ficheros en un arrays de estructuras. Una estructura por interfaz que se vea (interfaces separadas por una línea en blanco)
	if(nuevo->multiFile){
		char aux[TAM_LINE];
		int lineaVacia=1;  //flag que va a indicar si en la línea anterior se ha visto una línea en blanco (para crear una neuva estrutura). Se inicializa a 1 para crear la primera estructura (se supone que el fichero comienza sin líneas en blanco)
		while(!feof(fileOfPaths)){
	 		if(fgets(aux,TAM_LINE,fileOfPaths)!=NULL){ 
	 			if(lineaVacia && strlen(aux)>1){
	 				//Se ha visto una línea en blanco (en la línea anterior) y la línea actual tiene contenido (por si hay más de una línea en blanco de separación)
	 				//creo una nueva esctructura y la inicializo
	 				lineaVacia=0;
	 				nuevo->numInterfaces++;
	 				nuevo->interfaces=realloc(nuevo->interfaces,nuevo->numInterfaces*sizeof(struct interfaces_t));
	 				nuevo->interfaces[nuevo->numInterfaces-1].numFicheros=1;
	 				
	 				nuevo->interfaces[nuevo->numInterfaces-1].ficheros=NULL;
	 				//reservar memoria para un nuevo string
	 				nuevo->interfaces[nuevo->numInterfaces-1].ficheros=(char **)realloc(nuevo->interfaces[nuevo->numInterfaces-1].ficheros,nuevo->interfaces[nuevo->numInterfaces-1].numFicheros*sizeof(char*));
	 				//reservar memoria para el string en si
	 				nuevo->interfaces[nuevo->numInterfaces-1].ficheros[nuevo->interfaces[nuevo->numInterfaces-1].numFicheros-1]=(char*)malloc(TAM_LINE*sizeof(char));
	 				
	 				sscanf(aux, "%s", nuevo->interfaces[nuevo->numInterfaces-1].ficheros[nuevo->interfaces[nuevo->numInterfaces-1].numFicheros-1]);
	 				nuevo->interfaces[nuevo->numInterfaces-1].leidosTodos=0;
	 				//nuevo->interfaces[nuevo->numInterfaces-1].packet=NULL;
	 				nuevo->interfaces[nuevo->numInterfaces-1].numficheroParaAbrir=0;
	 				nuevo->interfaces[nuevo->numInterfaces-1].posThisPacket=0;
	 				stat(nuevo->interfaces[nuevo->numInterfaces-1].ficheros[nuevo->interfaces[nuevo->numInterfaces-1].numFicheros-1], &buf);
	 				nuevo->bytesTotalesFicheros+=(unsigned long long)buf.st_size;
	 				nuevo->interfaces[nuevo->numInterfaces-1].posALeerDeFichero=0;
	 			}else{
	 		 		if(strlen(aux)==1) lineaVacia=1; //si es una línea en blanco activo el flag lineaVacia 
	 			 	else{  //si no es una línea en blanco y en la línea anterior no hay blancos significa que el interfaz tiene más ficheros. Se añade el fichero a la estructura ya creada para ese interfaz
	 					lineaVacia=0;
	 					
                        if (nuevo->interfaces == NULL) {
							free(nuevo);
							return NULL;
						}
	 					nuevo->interfaces[nuevo->numInterfaces-1].numFicheros++;
	 					
	 					//reservar memoria para un nuevo string
	 					nuevo->interfaces[nuevo->numInterfaces-1].ficheros=(char **)realloc(nuevo->interfaces[nuevo->numInterfaces-1].ficheros,nuevo->interfaces[nuevo->numInterfaces-1].numFicheros*sizeof(char*));
	 					//reservar memoria para el string en si
	 					nuevo->interfaces[nuevo->numInterfaces-1].ficheros[nuevo->interfaces[nuevo->numInterfaces-1].numFicheros-1]=(char*)malloc(TAM_LINE*sizeof(char));
	 					
	 					sscanf(aux, "%s", nuevo->interfaces[nuevo->numInterfaces-1].ficheros[nuevo->interfaces[nuevo->numInterfaces-1].numFicheros-1]);
	 					stat(nuevo->interfaces[nuevo->numInterfaces-1].ficheros[nuevo->interfaces[nuevo->numInterfaces-1].numFicheros-1], &buf);
	 					nuevo->bytesTotalesFicheros+=(unsigned long long)buf.st_size;
	 				}
	 			}
	 		}
	 	}	
	}else{
		stat(nuevo->path, &buf);
		nuevo->bytesTotalesFicheros=(unsigned long long)buf.st_size;
	}
	
	//abro el primer fichero de cada interfaz y leo y guardo su primer paquete si es un archivo de archivos o abro el fichero si es una traza.
	 if (NDLTopen_next_multiple(nuevo, errbuf)!= 1) {
	 	//free(nuevo);
	 	NDLTclose(nuevo);
		return NULL;
	 }
	
	return nuevo;
}

/*
Función que comprueba que los parámetros sean correctos y crea una estructura NDLTdataEscritura_t con esos parámetros.

Devuelve la estructura NDLTdataEscritura_t creada o NULL en caso de error
*/
NDLTdataEscritura_t *NDLTabrirTrazaEscritura(char *pathOutput,char *formatOutput, int displayOutput,unsigned int snaplen,char *errbuf) {
	if(!displayOutput && !pathOutput){
		sprintf(errbuf, "Error: especifique la ruta del fichero de salida");
		return NULL;
	}
	
	int i,encontrado=0;
	char *nuevoFichero;
	if(!displayOutput){
		//Comprobar la ruta del fichero de salida y si hay fichero de salida
		for(i=(int)strlen(pathOutput)-1;i>=0;i--){
			if(pathOutput[i]=='/'){
				encontrado=1;
				break;
			}
		}
		if(encontrado){
			if(i==strlen(pathOutput)-1){
				sprintf(errbuf, "Error: especifique el nombre del fichero de salida");
				return NULL;
			}
			nuevoFichero = calloc(strlen(pathOutput)+1, 1);
			strncpy(nuevoFichero,pathOutput,i);
			DIR *dirp=opendir(nuevoFichero);
			if(dirp==NULL){
				sprintf(errbuf, "Error: No existe el directorio del fichero de salida indicado");
                free (nuevoFichero);
				return NULL;
			}else closedir(dirp);
			//realloc( nuevoFichero, 0 ); 
			free(nuevoFichero);
		}
	}
	
	int formatoSalida;
	if (!formatOutput || strcmp(formatOutput, NDLTFORMAT_PCAP_STR) == 0) formatoSalida = NDLTFORMAT_PCAP;
	else if (strcmp(formatOutput, NDLTFORMAT_DRIV_STR) == 0) formatoSalida = NDLTFORMAT_DRIV;
	else {
		sprintf(errbuf, "Error: formato de traza inválido");
		return NULL;
	}
	
	NDLTdataEscritura_t *nuevo = calloc(1,sizeof(NDLTdataEscritura_t));
	nuevo->fileFormato=formatoSalida;
    	if(!displayOutput) strncpy(nuevo->path, pathOutput, TAM_LINE);
	nuevo->displayOutput=displayOutput;
	nuevo->snaplen=snaplen;
	
	//abrir fichero de escritura
	if (nuevo->fileFormato == NDLTFORMAT_PCAP) {
		pcap_t *pcap_open=pcap_open_dead(DLT_EN10MB,CAPLEN);
		if(nuevo->displayOutput) nuevo->traceFile.pdh=pcap_dump_open(pcap_open, "-");
		else nuevo->traceFile.pdh=pcap_dump_open(pcap_open, nuevo->path);
		pcap_close(pcap_open);
	}else if(nuevo->fileFormato == NDLTFORMAT_DRIV){
		nuevo->traceFile.fh=fopen(nuevo->path, "w");
		if (!nuevo->traceFile.fh){
			sprintf(errbuf, "Error: no se pudo abrir el fichero de salida %s", nuevo->path);
			NDLTcloseEscritura(nuevo);
			return NULL;
		}
	}
	return nuevo;
}


/*
Función que abre el fichero que permite descartar paquetes a la hora de procesar.
Devuelve 1 si éxito, 0 si error
*/
int NDLTopenFileDiscards(NDLTdata_t *trazas,char *pathFile,char *errbuf) {
	char aux[TAM_LINE];
	if ((NULL == trazas) || (NULL == pathFile)){ 
		sprintf(errbuf, "Error: no se pudo abrir el fichero: %s.\n", pathFile);
		return 0;
	}
	trazas->filePacketsToDiscard = fopen(pathFile, "r");
	if (NULL == trazas->filePacketsToDiscard){
		sprintf(errbuf, "Error: no se pudo abrir el fichero: %s.\n", pathFile);
		return 0;
	}
	
	//leo la primera línea del fichero, para guardar el numero del primer paquete a descartar
	if(fgets(aux, TAM_LINE, trazas->filePacketsToDiscard)==NULL){
		sprintf(errbuf, "Error leyendo el fichero: %s. Esta vacio \n", pathFile);
		return 0;
	}
	trazas->nextPacketToDiscard=atoll(aux);
	return 1;
}

/*
Función que indica el modo en el que salen los mensajes de error del programa (por ejemplo de la función NDLTloop). Si es 1 salen por la salida de error (stderr) y si es 0, no se muestran los mensajes de error.
Devuelve 1 en caso de éxito, 0 en caso de que la estrcutura NDLTdata_t no exista
*/
//int setErrorOutput(NDLTdata_t *trazas,int outputStderr){ 
int setErrorOutput(NDLTdata_t *trazas,FILE *outputStderr){ 
	if (NULL == trazas) return 0;
	trazas->fileForError=outputStderr;
	return 1;
}

/*
Función interna que realiza todas las comprobaciones para ver si se llama al callback del usuario con un paquete en concreto o no. Comprueba si el programa está saltando a un paquete en concreto, comprueba si se ha indicado un filtro y comprueba si hay un fichero con paquetes a descartar.
Codigos de resultado:
	- Devuelve 1 en caso de exito
	- Devuelve -1 si se ha producido algún error en la función checkPacketInFile(), por ejemplo que el fichero de descartes no esté ordenado.
	- Devuelve 2 en caso de éxito y si está activa alguna función de obtener el siguiente paquete (NDLTnext() o NDLTnext_ex()), es decir, el usuario ha llamado a alguna de esas dos funciones.
*/
static int loop_aux(NDLTdata_t *trazas,struct NDLTpkthdr pkthdr,const u_char *packet,packet_handler callback, u_char *user){
	int codigoResult;
	
	//llamar al callback si se cumplen una serie de cosas. Si se está saltando a un paquete se llama al callback
	if(trazas->jumpPacketActivated){ 
		if(checkPacketInFile(trazas)==-1) return(-1);
		callback(user, &pkthdr, packet);
	}else{
		//Se comprueba si el paquete actual hay que descartarlo
		codigoResult=checkPacketInFile(trazas);
		
		if(codigoResult==-1) return(-1);
		else if(codigoResult==0) {
			//No se descarta por fichero de descartes pero se puede descartar por filtro, si es que se ha indicado un filtro
			if(trazas->pcapFilterString!=NULL){
				if(NDLTfilter(&trazas->filtroPcapCompilado, &pkthdr, packet)){
					if(trazas->nextPacketActive==1 ) return 2; //para salir del bucle si se ha llamado a NDLTnext()
					else callback(user, &pkthdr, packet); //No se descarta tampoco por filtro asi que se hace el callback
				}else trazas->numPacketsDiscarded++;
			}else{
				if(trazas->nextPacketActive==1 ) return 2; //para salir del bucle si se ha llamado a NDLTnext()
				else callback(user, &pkthdr, packet);
			}
		}else trazas->numPacketsDiscarded++;  //se aumenta el contador de descartados
	}
	return 1;
}

/*
Función interna que comprueba si se han acabado de leer todos los ficheros de todas las interfaces.
Si es 0 aun no hemos acabado de leer todos los ficheros. Si es 1 todos los ficheros de todas las interfaces han sido leidos.
*/
static int checkFin(NDLTdata_t *trazas){
	for(int i=0;i<trazas->numInterfaces;i++){
		if(trazas->interfaces[i].leidosTodos!=1) return 0;
	}
	return 1;
}

/*Códigos de respuesta:
	- Devuelve 1 en éxito 
	- Devuelve 2 en éxito cuando estamos en la función NDLTnext() o NDLTnext_ex()
	- Devuelve otros valores en caso de error
*/
int NDLTloop(NDLTdata_t *trazas, packet_handler callback, u_char *user) {
	unsigned char buf[MAX_PACKET_LEN];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *hdr;
	const u_char *packet;
	struct NDLTpkthdr pkthdr;
	unsigned long long  posALeerDeFichero = 0;
	unsigned long long  nuevaPosALeerDeFichero = 0;
	int i;
	int numInterfazElegido=0, resultado=0,resLeerPaquete=0;
	long double ts,tsMinimo=0;
	
	header_RAW_t headRaw;
	
	// Se supone que el fichero, o el primero de ellos, está ya abierto
	// Esto permite por ejemplo llamar a NDLTjumpToPacket() y después a NDLTloop()
	// Si hiciéramos aquí un while(NDLTopen_next()) nos cargaríamos lo que hubiera hecho antes un NDLTjumpToPacket()
	while (1) {
		if(trazas->multiFile){
			//Comprobar si para todos los interfaces esta variable esta a 1 y si es asi salir del bucle infinito
			if(checkFin(trazas)){
				if(trazas->nextPacketActive==1) return -2;
				else break;
			}
			
			//elijo el primer paquete que vea como minimo (del primer interfaz que tenga el fichero abierto, es decir, la variable leidosTodos a 0)
			for(i=0;i<trazas->numInterfaces;i++){  
				if(!trazas->interfaces[i].leidosTodos){
					tsMinimo = trazas->interfaces[i].pkthdr.ts.tv_sec+trazas->interfaces[i].pkthdr.ts.tv_nsec/1000000000.0L;
					numInterfazElegido=i;
					break;
				}
			}
			//comprobar cual es el paquete con menor timestamp de los de los interfaces y guardar el número del interfaz en 'numInterfazElegido'
			for(i=numInterfazElegido+1;i<trazas->numInterfaces;i++){
				ts=trazas->interfaces[i].pkthdr.ts.tv_sec+trazas->interfaces[i].pkthdr.ts.tv_nsec/1000000000.0L;
				if(!trazas->interfaces[i].leidosTodos && ts<tsMinimo){
					tsMinimo=ts;
					numInterfazElegido=i;
				}
			}
		}
		
		if (trazas->fileFormato==NDLTFORMAT_PCAP){ //si la traza es pcap
			if(trazas->multiFile){
				//Se incrementa el número de paquetes leídos
				trazas->numPktsLeidos++;
				
				// Incrementar el contador de bytes que se han leido
				nuevaPosALeerDeFichero = (unsigned long long)ftello(pcap_file(trazas->interfaces[numInterfazElegido].trazaAbierta.ph));
				if (nuevaPosALeerDeFichero > trazas->interfaces[numInterfazElegido].posALeerDeFichero) trazas->bytesTotalesLeidos += nuevaPosALeerDeFichero - trazas->interfaces[numInterfazElegido].posALeerDeFichero;
				else trazas->bytesTotalesLeidos += nuevaPosALeerDeFichero;
				trazas->interfaces[numInterfazElegido].posALeerDeFichero=nuevaPosALeerDeFichero;
				
				//llamar a la función que llamará al callback del usuario
				resultado=loop_aux(trazas,trazas->interfaces[numInterfazElegido].pkthdr,trazas->interfaces[numInterfazElegido].packet.pkt,callback,user);
				if(resultado==-1) return resultado;
				if(resultado==2){
					trazas->pkthdr_next.caplen=trazas->interfaces[numInterfazElegido].pkthdr.caplen;	
					trazas->pkthdr_next.len=trazas->interfaces[numInterfazElegido].pkthdr.len;
					trazas->pkthdr_next.ts.tv_sec=trazas->interfaces[numInterfazElegido].pkthdr.ts.tv_sec;
					trazas->pkthdr_next.ts.tv_nsec=trazas->interfaces[numInterfazElegido].pkthdr.ts.tv_nsec;	
					
					memcpy(trazas->packet_next, trazas->interfaces[numInterfazElegido].packet.pkt, trazas->interfaces[numInterfazElegido].pkthdr.caplen);
					//trazas->tamPacket=trazas->interfaces[numInterfazElegido].pkthdr.caplen;
				}
				
				// actualizar la posicion de paquete con la del siguiente
				trazas->interfaces[numInterfazElegido].posThisPacket = (unsigned long long)ftello(pcap_file(trazas->interfaces[numInterfazElegido].trazaAbierta.ph));
				
				//se va a leer el siguiente paquete del interfaz que ha sido elegido con menor timestamp
				resLeerPaquete=leerPaquetePcap(trazas,numInterfazElegido);
				if(resLeerPaquete==0){
					//se ha terminado el fichero
					//abrir el siguiente fichero, si hay mas ficheros disponibles
					if(trazas->interfaces[numInterfazElegido].numficheroParaAbrir < trazas->interfaces[numInterfazElegido].numFicheros){
						//Se cierra el fichero que ha terminado
						pcap_close(trazas->interfaces[numInterfazElegido].trazaAbierta.ph);
						//Se abre el siguiente fichero de la lista
						trazas->interfaces[numInterfazElegido].trazaAbierta.ph = pcap_open_offline(trazas->interfaces[numInterfazElegido].ficheros[trazas->interfaces[numInterfazElegido].numficheroParaAbrir], errbuf);
						if (!trazas->interfaces[numInterfazElegido].trazaAbierta.ph) {
							fprintf(trazas->fileForError, "Error: no se pudo abrir el fichero %s. Error: %s\n", trazas->interfaces[numInterfazElegido].ficheros[trazas->interfaces[numInterfazElegido].numficheroParaAbrir],errbuf);
							return 0;
						}
						
						if(numInterfazElegido==0) trazas->contFiles++;
						//Se aumenta el contador que indica el siguiente fichero a abrir
						trazas->interfaces[numInterfazElegido].numficheroParaAbrir++;
						
						//Se lee el primer paquete del nuevo archivo abierto
						leerPaquetePcap(trazas,numInterfazElegido);
					}else{  //ya se han abierto todos los ficheros de ese interfaz
						trazas->interfaces[numInterfazElegido].leidosTodos=1;
					}
				}
				
				// si se ha activado este flag indica que hay que salir del loop en el caso de que se esté saltando a un paquete
				if (trazas->shouldBreakLoopFlag) {
					trazas->shouldBreakLoopFlag = 0;
					trazas->jumpPacketActivated=0;
					return 1;
				}
			}
			else{   //solo se ha pasado un fichero (traza) como parámetro
				while (pcap_next_ex(trazas->traceFile.ph, &hdr, &packet)!=-2) {  //leer paquete
					//Se incrementa el número de paquetes leídos
					trazas->numPktsLeidos++;
					
					// Incrementar el contador de bytes que se han leido
					nuevaPosALeerDeFichero = (unsigned long long)ftello(NDLTfile(trazas));
					if (nuevaPosALeerDeFichero > posALeerDeFichero) trazas->bytesTotalesLeidos += nuevaPosALeerDeFichero - posALeerDeFichero;
					else trazas->bytesTotalesLeidos += nuevaPosALeerDeFichero;
					posALeerDeFichero = nuevaPosALeerDeFichero;
					
					//rellenar el NDLTpkthdr
					pkthdr.caplen=hdr->caplen;
					if(hdr->caplen> MAX_PACKET_LEN ){
						fprintf(trazas->fileForError, "La longitud del paquete (%d) supera los limites (%d). \n", hdr->caplen, MAX_PACKET_LEN);
						return 0;
					}
					pkthdr.len=hdr->len;
					pkthdr.ts.tv_sec=hdr->ts.tv_sec;
					pkthdr.ts.tv_nsec=hdr->ts.tv_usec*1000;
					
					//llamar a la función que llamará al callback del usuario
					resultado=loop_aux(trazas,pkthdr,packet,callback,user);
					if(resultado==-1) return resultado;
					
					// actualizar la posicion de paquete con la del siguiente
					trazas->posThisPacket = (unsigned long long)ftello(NDLTfile(trazas));
					
					// si se ha activado este flag indica que hay que salir del loop en el caso de que se esté saltando a un paquete
					if (trazas->shouldBreakLoopFlag) {
						trazas->shouldBreakLoopFlag = 0;
						trazas->jumpPacketActivated=0;
						return 1;
					}
					
					if(trazas->nextPacketActive==1 && resultado==2){
						
						trazas->pkthdr_next.caplen=hdr->caplen;	
						trazas->pkthdr_next.len=hdr->len;
						trazas->pkthdr_next.ts.tv_sec=hdr->ts.tv_sec;
						trazas->pkthdr_next.ts.tv_nsec=hdr->ts.tv_usec*1000;	
							
						memcpy(trazas->packet_next,packet, hdr->caplen);
						//trazas->tamPacket= hdr->caplen;
      						return resultado; //para salir del bucle si se ha llamado a NDLTnext()
      					}
                		}
                		if(trazas->nextPacketActive==1) return -2;
                		break;
			}
		}else if (trazas->fileFormato==NDLTFORMAT_DRIV) {  //si la traza es driv
			if(trazas->multiFile){
				//Se incrementa el número de paquetes leídos
				trazas->numPktsLeidos++;
				
				// Incrementar el contador de bytes que se han leido
				trazas->bytesTotalesLeidos += sizeof(header_RAW_t) + trazas->interfaces[numInterfazElegido].pkthdr.caplen; 
				
				//llamar a la función que llamará al callback del usuario
				resultado=loop_aux(trazas,trazas->interfaces[numInterfazElegido].pkthdr,trazas->interfaces[numInterfazElegido].packet.buffer,callback,user);
				if(resultado==-1) return resultado;
				if(resultado==2){
					trazas->pkthdr_next.caplen=trazas->interfaces[numInterfazElegido].pkthdr.caplen;	
					trazas->pkthdr_next.len=trazas->interfaces[numInterfazElegido].pkthdr.len;
					trazas->pkthdr_next.ts.tv_sec=trazas->interfaces[numInterfazElegido].pkthdr.ts.tv_sec;
					trazas->pkthdr_next.ts.tv_nsec=trazas->interfaces[numInterfazElegido].pkthdr.ts.tv_nsec;	
					
					memcpy(trazas->packet_next, trazas->interfaces[numInterfazElegido].packet.buffer, trazas->interfaces[numInterfazElegido].pkthdr.caplen);
					//trazas->tamPacket=trazas->interfaces[numInterfazElegido].pkthdr.caplen;
				}
				
				// actualizar la posicion de paquete con la del siguiente
				trazas->interfaces[numInterfazElegido].posThisPacket = (unsigned long long)ftello(trazas->interfaces[numInterfazElegido].trazaAbierta.fh);
				 
				//se va a leer el siguiente paquete del interfaz que ha sido elegido con menor timestamp
				resLeerPaquete=leerPaqueteFile(trazas,numInterfazElegido);
				if(resLeerPaquete==0 || resLeerPaquete==-1) return -1;
				if(feof(trazas->interfaces[numInterfazElegido].trazaAbierta.fh) || resLeerPaquete==1){
					//se ha terminado el fichero
					//abrir el siguiente fichero, si hay mas ficheros disponibles
					if(trazas->interfaces[numInterfazElegido].numficheroParaAbrir<trazas->interfaces[numInterfazElegido].numFicheros){
						//Se cierra el fichero que ha terminado
						fclose(trazas->interfaces[numInterfazElegido].trazaAbierta.fh);
						//Se abre el siguiente fichero de la lista
						trazas->interfaces[numInterfazElegido].trazaAbierta.fh=fopen(trazas->interfaces[numInterfazElegido].ficheros[trazas->interfaces[numInterfazElegido].numficheroParaAbrir],"r");
						if(!trazas->interfaces[numInterfazElegido].trazaAbierta.fh){ 
							fprintf(trazas->fileForError, "Error: no se pudo abrir el fichero %s\n", trazas->interfaces[numInterfazElegido].ficheros[trazas->interfaces[numInterfazElegido].numficheroParaAbrir]);
							return 0;
						}
						
						if(numInterfazElegido==0) trazas->contFiles++;
						//Se aumenta el contador que indica el siguiente fichero a abrir
						trazas->interfaces[numInterfazElegido].numficheroParaAbrir++;
						
						//Se lee el primer paquete del nuevo archivo abierto
						resLeerPaquete=leerPaqueteFile(trazas,numInterfazElegido);
						if(resLeerPaquete==0 || resLeerPaquete==-1) return -1;
					}else{  //ya se han abierto todos los ficheros de ese interfaz
						trazas->interfaces[numInterfazElegido].leidosTodos=1;
					}
				}
				
				// si se ha activado este flag indica que hay que salir del loop en el caso de que se esté saltando a un paquete
				if (trazas->shouldBreakLoopFlag) {
					trazas->shouldBreakLoopFlag = 0;
					trazas->jumpPacketActivated=0;
					return 1;
				}
			}else{   //solo se ha pasado un fichero (traza) como parámetro
				while (!feof(trazas->traceFile.fh)) {
					//leer la cabecera del paquete
					if(fread(&headRaw,1,sizeof(header_RAW_t),trazas->traceFile.fh) !=sizeof(header_RAW_t)) break;
					if(headRaw.secs==0 && headRaw.nsecs==0) break;
					if( headRaw.caplen > MAX_PACKET_LEN ){
						fprintf(trazas->fileForError, "El caplen del paquete (%d) supera la longitud, len,  del paquete (%d).\n", headRaw.caplen, headRaw.len);
						//si falla en el primer paquete puede ser porque el fichero sea un fichero de ficheros
						if(trazas->numPktsLeidos==0) fprintf(trazas->fileForError, "Compruebe que el fichero no es un fichero de ficheros.\n");
						return (-1);
					}
					
					//Se incrementa el número de paquetes leídos
					trazas->numPktsLeidos++;
					
					// Incrementar el contador de bytes que se han leido
					trazas->bytesTotalesLeidos += sizeof(header_RAW_t);
               				
					if( headRaw.caplen > 0 ){
						//rellenar el NDLTpkthdr
						pkthdr.caplen=headRaw.caplen;
						pkthdr.len=headRaw.len;
						pkthdr.ts.tv_sec=headRaw.secs;
						pkthdr.ts.tv_nsec=headRaw.nsecs;
						// leer el paquete
						if (fread(buf, 1, headRaw.caplen, trazas->traceFile.fh) != headRaw.caplen) {
							fprintf(trazas->fileForError, "Error leyendo %u bytes\n", headRaw.caplen);
							return(-1);
						}
						
						// Incrementar el contador de bytes que se han leido
						trazas->bytesTotalesLeidos += headRaw.caplen; 
						 
						//llamar a la función que llamará al callback del usuario
						resultado=loop_aux(trazas,pkthdr,buf,callback,user);
						if(resultado==-1) return resultado;
					} else{ 
						fprintf(trazas->fileForError, "Warning: caplen=0 !!\n");
						trazas->numPacketsDiscarded++;    
						if(checkPacketInFile(trazas)==-1) return(-1);
					}
					
					// actualizar la posicion de paquete con la del siguiente
					trazas->posThisPacket = (unsigned long long)ftello(NDLTfile(trazas));
					
					// si se ha activado este flag indica que hay que salir del loop en el caso de que se esté saltando a un paquete
					if (trazas->shouldBreakLoopFlag) {
						trazas->shouldBreakLoopFlag = 0;
						trazas->jumpPacketActivated=0;
						return 1;
					}
					if(trazas->nextPacketActive==1 && resultado==2){
						trazas->pkthdr_next.caplen=pkthdr.caplen;	
						trazas->pkthdr_next.len=pkthdr.len;
						trazas->pkthdr_next.ts.tv_sec=pkthdr.ts.tv_sec;
						trazas->pkthdr_next.ts.tv_nsec=pkthdr.ts.tv_nsec;
							
						memcpy(trazas->packet_next, buf, pkthdr.caplen);
						//trazas->tamPacket=pkthdr.caplen;
							
						return resultado; //para salir del bucle si se ha llamado a NDLTnext()
					}
				}
				if(trazas->nextPacketActive==1) return -2;
				break;
			}
		}
		//trazas->posThisPacket = 0;
		if(trazas->nextPacketActive==1 && resultado==2){
			return resultado; //para salir del bucle si se ha llamado a NDLTnext()
		}
	}
	return 1;
}

int NDLTnext_ex(NDLTdata_t *trazas, const struct NDLTpkthdr **h,const u_char **pkt_data){
	int resultado;
	u_char *user=NULL;
	packet_handler callback=NULL;
	
	trazas->nextPacketActive=1;
	resultado= NDLTloop(trazas, callback, user); 
	
	if(resultado==2){
		*h=&(trazas->pkthdr_next);
		
		*pkt_data = trazas->packet_next;
		//reservo memoria para el paquete
		//*pkt_data=(char *)malloc(trazas->pkthdr_next.caplen+1);
		//memcpy(*pkt_data, trazas->packet_next,trazas->pkthdr_next.caplen);
		
		return 1;
	}else return resultado;
}

const u_char *NDLTnext(NDLTdata_t *trazas, const struct NDLTpkthdr **h){
	int resultado;
	u_char *user=NULL;
	packet_handler callback=NULL;
	
	trazas->nextPacketActive=1;
	resultado= NDLTloop(trazas, callback, user); 
	
	if(resultado==2){
		
		*h=&(trazas->pkthdr_next);
		return trazas->packet_next;	
	}
	else{
		return NULL;
	}
}


/*
Función que cierra todos los elementos abiertos, como el pcap_t en caso de que las trazas sean pcap, o el descriptor de fichero. Tambien libera el registro de indices
*/
void NDLTclose(NDLTdata_t *trazas) {
	if (NULL == trazas) return;
	if (trazas->multiFile) fclose(trazas->fileOfPaths);
	NDLTclose_last(trazas);
	if (NULL != trazas->fileIndex) fclose(trazas->fileIndex);
	
	//si se ha indicado un fichero con paquetes a descartar se cierra
	if(trazas->filePacketsToDiscard!=NULL) fclose(trazas->filePacketsToDiscard);
	free(trazas->indices);
	free(trazas->interfaces);
	free(trazas);
}

void NDLTcloseEscritura(NDLTdataEscritura_t *trazas) {
	if (NULL == trazas) return;
	if (trazas->fileFormato==NDLTFORMAT_PCAP) { //si la traza es pcap
		if(!trazas->displayOutput) pcap_dump_close(trazas->traceFile.pdh);
	}
	else fclose(trazas->traceFile.fh);
	free(trazas);
}


/*
Función que devuelve el descriptor de fichero que se está procesando en ese momento. 
*/
FILE *NDLTfile(NDLTdata_t *trazas){
	if (NULL == trazas) return NULL;
	if(trazas->multiFile){
		if (trazas->fileFormato==NDLTFORMAT_PCAP) return pcap_file(trazas->interfaces[0].trazaAbierta.ph);
		else return trazas->interfaces[0].trazaAbierta.fh;
	}else{
		if (trazas->fileFormato==NDLTFORMAT_PCAP) return pcap_file(trazas->traceFile.ph);
		else return trazas->traceFile.fh;
	}
}

// Función que devuelve el número de archivo que se está procesando en ese momento
int NDLTfileNumber(NDLTdata_t *trazas) {
	if (NULL == trazas) return -1;
	return trazas->contFiles;
}

// Función que devuelve el tamaño del archivo que se está procesando en ese momento
unsigned long long NDLTfileSize(NDLTdata_t *trazas) {
	struct stat buf;
	if (NULL == trazas) return 0;
	if(trazas->multiFile) 	stat(trazas->interfaces[0].ficheros[trazas->interfaces[0].numficheroParaAbrir-1], &buf);	
	else stat(trazas->path, &buf);	
	return (unsigned long long)buf.st_size;
}

//Función que devuelve el número de paquetes descartados de la traza o trazas (tanto paquetes descartados como paquetes que no pasan el filtro)
unsigned long long NDLTpacketsDiscarded(NDLTdata_t *trazas){
	if (NULL == trazas) return 0;
	return trazas->numPacketsDiscarded;
}


// Función que devuelve el número de bytes totales leídos de todos los ficheros de la traza
unsigned long long NDLTbytesRead(NDLTdata_t *trazas) {
	if (NULL == trazas) return 0;
	return trazas->bytesTotalesLeidos;
}

// Función que devuelve el número de bytes totales de todos los ficheros de la traza (el tamaño total de todos los ficheros, o del fichero de traza en caso de ser solo uno)
unsigned long long NDLTtotalBytes(NDLTdata_t *trazas){
	if (NULL == trazas) return 0;
	return trazas->bytesTotalesFicheros;
}

// Función que devuelve la posición en bytes en el fichero actual del comienzo del paquete que se acaba de leer. Es diferente de la posición de lectura en el fichero, que sería la del siguiente paquete
unsigned long long NDLTposThisPacket(NDLTdata_t *trazas) {
	if (NULL == trazas) return 0;
	return trazas->posThisPacket;
}

// Funcion para especificar el fichero de indices en caso de existir. Devuelve 1 si exito, 0 si error (por ejemplo al abrir ese fichero de indices)
int NDLTsetIndexFile(NDLTdata_t *trazas, char *indexFilePath) {
	if ((NULL == trazas) || (NULL == indexFilePath)) return 0;
	if (NULL != trazas->fileIndex) {
		fclose(trazas->fileIndex);
		free(trazas->indices);
        trazas->indices = NULL;
		trazas->numIndicesLeidos = 0;
		trazas->maxIndicesCreados = 0;
	}
	
	trazas->fileIndex = fopen(indexFilePath, "r");
	if (NULL == trazas->fileIndex) return 0;
	
	unsigned long long  numPacket, bytesPosition;
	int fileIndex;
	while (fscanf(trazas->fileIndex, "%llu %d %llu", &numPacket, &fileIndex, &bytesPosition) == 3) {
		if (trazas->numIndicesLeidos >= trazas->maxIndicesCreados) {
			// No hay espacio para guardarlo, reservar mas
			struct NDLTindexElement *nuevoArrayIndices;
			nuevoArrayIndices = realloc(trazas->indices, (trazas->maxIndicesCreados + BLOQUE_INDICES)*sizeof(struct NDLTindexElement));
			if (NULL == nuevoArrayIndices) {
				free(trazas->indices);
				fclose(trazas->fileIndex);
				trazas->numIndicesLeidos = trazas->maxIndicesCreados = 0;
				return 0;
			}
			trazas->indices = nuevoArrayIndices;
			trazas->maxIndicesCreados += BLOQUE_INDICES;
		}
		trazas->indices[trazas->numIndicesLeidos].numPacket = numPacket;
		trazas->indices[trazas->numIndicesLeidos].bytesPosition = bytesPosition;
		trazas->indices[trazas->numIndicesLeidos].fileIndex = fileIndex;
		trazas->numIndicesLeidos++;
	}
	return 1;
}

// Función interna que devuelve el elemento de índice anterior al número de paquete especificado y más cercano. Si hay que empezar por el principio devuelve NULL
static struct NDLTindexElement *NDLTgetIndexBeforePacket(NDLTdata_t *trazas, unsigned long long pktNumber) {
	if (NULL == trazas) return NULL;
	
	struct NDLTindexElement *eltoIndice = NULL;
	int posIndice = 0;
	while (posIndice < trazas->numIndicesLeidos) {
		if (trazas->indices[posIndice].numPacket > pktNumber) break;
		eltoIndice = trazas->indices + posIndice;
		trazas->numPktsLeidos=trazas->indices[posIndice].numPacket;
		posIndice++;
	}
	return eltoIndice;
}

struct internalCallbackAvance_params_t {
	NDLTdata_t  		*trazas;
	unsigned long long  	pktInicial;
	unsigned long long  	pktObjetivo;
};

// Vuelve al comienzo de la traza
void NDLTrewind(NDLTdata_t *trazas) {
	char errbuf[PCAP_ERRBUF_SIZE];
	
	NDLTclose_last(trazas);
	rewind(trazas->fileOfPaths);
	trazas->contFiles = 0;
	NDLTopen_next(trazas, errbuf);
}

// Funcion interna para usar de callback de un NDLTloop() al avanzar en los ficheros en un jump hasta el punto correcto cuando el índice no da la respuesta exacta
static void internalCallbackAvance(u_char *user, const struct NDLTpkthdr *h, const u_char *bytes) {
	struct internalCallbackAvance_params_t  *params = (struct internalCallbackAvance_params_t  *)user;
	static unsigned long long   pktActual = 1;
	
	if (pktActual == 1) pktActual = params->pktInicial;
	if (pktActual == params->pktObjetivo-1) NDLTbreakloop(params->trazas);
	else pktActual++;
}

// Salta en la lectura al paquete que se le indica. Devuelve 0 si error, 1 si exito
int NDLTjumpToPacket(NDLTdata_t *trazas, unsigned long long pktNumber) {
	struct NDLTindexElement     *eltoIndice;
	char errbuf[PCAP_ERRBUF_SIZE];
	char aux[TAM_LINE];
	if (pktNumber == 0) return 0;
	
	//if(trazas->multiFile) NDLTrewind(trazas);
	if (pktNumber == 1) return 1;
	eltoIndice = NDLTgetIndexBeforePacket(trazas, pktNumber);
	if (eltoIndice) {
		// Avanza hasta el fichero correcto
		while (eltoIndice->fileIndex != NDLTfileNumber(trazas)) {
			NDLTopen_next(trazas, errbuf); // Abro el siguiente, hasta llegar al que busco
			// Avanzo así para mantener coherencia en la estructura respecto a la posición en la que se está leyendo en el fichero de lista de ficheros
		}
    	
        //avanzar el fichero de descartes (si existe) hasta un número de paquete menor del indice en que se ha quedado
        if(trazas->filePacketsToDiscard!=NULL){
            while(trazas->nextPacketToDiscard<eltoIndice->numPacket){
                if(!feof(trazas->filePacketsToDiscard)){
                    if (fgets(aux, TAM_LINE, trazas->filePacketsToDiscard)==NULL) {
                        fprintf(trazas->fileForError, "Terminado el fichero de paquetes a descartar\n");
                        break;
                    }
                    if(trazas->nextPacketToDiscard>atoll(aux)){
                        //if(trazas->errorToStdErr) fprintf(stderr, "Error: el fichero con los paquetes a descartar no está ordenado\n");
                        fprintf(trazas->fileForError, "Error: el fichero con los paquetes a descartar no está ordenado\n");
                        return 0;
                    }
                    trazas->nextPacketToDiscard=atoll(aux);
                }
                else break;
            }
        }
        // Avanzar ahora hasta el segmento en cuestión
        if(eltoIndice->bytesPosition!=0 && fseeko(NDLTfile(trazas), (off_t)eltoIndice->bytesPosition, SEEK_SET) == -1) return 1;
    }
    	
    // Desde aqui hay que ir uno a uno
    if((eltoIndice && eltoIndice->numPacket<pktNumber) || eltoIndice==NULL){
        struct internalCallbackAvance_params_t  params;
        params.trazas = trazas;
        params.pktInicial = (eltoIndice == NULL)?1:eltoIndice->numPacket;
        params.pktObjetivo = pktNumber;
        trazas->jumpPacketActivated=1;
        NDLTloop(trazas, internalCallbackAvance, (u_char*)&params);
    }
    	
    trazas->bytesTotalesLeidos = 0; // No es de fiar porque NDLTloop() lo habrá hecho avanzar pero contando solo este ficheor, no los anteriores, así que mejor se reinicia y se poner en la documentación que se hace esto tras un jump
    	
    return 1;
}

// Equivalente a pcap_breakloop(), sirve para activar un flag que hace que se salga de NDLTloop()
void NDLTbreakloop(NDLTdata_t *trazas) {
	if (NULL == trazas) return;
	trazas->shouldBreakLoopFlag = 1;
}

//Función que escribe en un fichero (o salida estándar) un paquete. Equivalente a pcap_dump
void NDLTdump(NDLTdataEscritura_t *trazas, const struct NDLTpkthdr *h, const u_char *sp){
	if(trazas->fileFormato==NDLTFORMAT_PCAP){
		struct pcap_pkthdr header;
		header.ts.tv_sec=h->ts.tv_sec;
		header.ts.tv_usec=(suseconds_t)h->ts.tv_nsec/1000;
		if(h->caplen<trazas->snaplen) header.caplen=(u_int32_t)h->caplen;
		else header.caplen=trazas->snaplen;
		header.len=(u_int32_t)h->len;
		pcap_dump( (u_char*)trazas->traceFile.pdh, &header, sp);
	}else if (trazas->fileFormato==NDLTFORMAT_DRIV) {
		FILE *stream;
		if(trazas->displayOutput) stream=stdout;
		else stream=trazas->traceFile.fh;
		
		fwrite(&h->ts.tv_sec,sizeof(u_int32_t),1,stream);	
		fwrite(&h->ts.tv_nsec,sizeof(u_int32_t),1,stream);
		if(h->caplen<trazas->snaplen) fwrite(&h->caplen,sizeof(u_int16_t),1,stream);
		else fwrite(&trazas->snaplen,sizeof(u_int16_t),1,stream);
		fwrite(&h->len,sizeof(u_int16_t),1,stream);
		if(h->caplen<trazas->snaplen) fwrite(sp,sizeof(u_char),h->caplen,stream);
		else fwrite(sp,sizeof(u_char),trazas->snaplen,stream);
	}
}

// Devuelve el numero de paquete en las trazas del ultimo leido
unsigned long long NDLTpktNumber(NDLTdata_t *trazas) {
	if (!trazas) return 0;
	return trazas->numPktsLeidos;
}

