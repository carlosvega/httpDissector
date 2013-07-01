//
//  NDleeTrazas.c
//  
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


#define NDLTFORMAT_PCAP    1
#define NDLTFORMAT_DRIV    2

#define MAX_PACKET_LEN 	2048
#define CAPLEN 		65535

#define BLOQUE_INDICES	1000     // Cantidad de indices a reservar cada vez

#define NUM_FICH_INTERFACE 3000   //Cantidad de ficheros que puede haber por interfaz

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
	char ficheros[NUM_FICH_INTERFACE][TAM_LINE];	// array con el nombre de los ficheros de trazas de la interfaz
	int numFicheros;				// contador de ficheros
	union descriptores 	trazaAbierta;		// va a contener el descriptor de fichero que está abierto en ese momento
	int numficheroParaAbrir;  			// numero de indice que indica el fichero que toca abrir en ese momento 
	struct NDLTpkthdr pkthdr;			// contiene el header del paquete que se ha leido del fichero abierto
	union contenidoPaquete packet;			// contiene los datos del paquete que se ha leido del fichero abierto
	int leidosTodos;				// flag que indica si ya se han leido todos los ficheros del array 'ficheros'
	unsigned long long posThisPacket;		// posición en bytes en el fichero actual del comienzo del paquete que se acaba de leer. Es diferente de la posición de lectura en el fichero, que sería la del siguiente paquete
	unsigned long long posALeerDeFichero;		// posicion en la que se queda el fichero después de leer un paquete
};

/*
 * Función que compila un filtro BPF. Es un wrapper para pcap_compile_nopcap. Tiene unos requerimientos especiales (el resto de parámetros, igual que en pcap_compile). Se usa para poder filtrar por 'n' filtros, ya que NDLTloop solo permite filtrar por uno solo:
 * 
 * - snaplen: si es una captura en RAW, hay que saber qué snaplen se ha puesto y meterlo a mano.
 * - linktype: lo mismo. Se pueden utilizar los de PCAP (DLT_<algo>). Ej: DLT_EN10MB para ethernet.
 * 
 *  Devuelve 0 si no hay error.
 */
 int NDLTcompile(int snaplen_arg, int linktype_arg, struct bpf_program *program, const char *buf, int optimize, bpf_u_int32 mask) {
	return pcap_compile_nopcap(snaplen_arg, linktype_arg, program, buf, optimize, mask);
}

// Dado un paquete, se aplica el filtro BPF. Devuelve 0 si el paquete no pasa el filtro y distinto de 0 en caso contrario.
int NDLTfilter(struct bpf_program *fp, const struct NDLTpkthdr *h, const u_char *pkt) {
	struct bpf_insn *fcode = fp->bf_insns;

	if (fcode != NULL) 
		return (bpf_filter(fcode, pkt, h->len, h->caplen));
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
		}
	}else if(data->fileFormato == NDLTFORMAT_PCAP){
		pcap_close(data->traceFile.ph);
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
	- Si es 0 hay algún error (o bien el caplen es demasiado grande o se ha producido un error al leer el paquete) y se saldrá del programa
	- Si es 1 significa que hemos llegado al pseudo paquete del final del fichero (segundos y nanosegundos son 0) y se tiene que cerrar el fichero
	- Si es 2 hay éxito o se ha terminado el fichero
*/
static int leerPaqueteFile(NDLTdata_t *trazas,int indice){
	u_int32_t secs,nsecs;
	u_int16_t len,caplen;
	
	if( fread(&secs,1,sizeof(u_int32_t),trazas->interfaces[indice].trazaAbierta.fh)!=sizeof(u_int32_t)){ 
		//final de fichero
		if(feof(trazas->interfaces[indice].trazaAbierta.fh)) return 2;
		fprintf(trazas->fileForError, "Error al leer los segundos del fichero %s del interfaz %d - Posicion: %llu\n", trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1], (indice-1),(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
		return 0;
	}
	if( fread(&nsecs,1,sizeof(u_int32_t),trazas->interfaces[indice].trazaAbierta.fh)!=sizeof(u_int32_t)){
		fprintf(trazas->fileForError, "Error al leer los nanosegundos del fichero %s del interfaz %d - Posicion: %llu", trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1], (indice-1),(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
		 return 0;
	}
	
	if( (secs==0) && (nsecs==0)){ 
		// pseudo paquete del final. Saltarlo y cerrar el fichero
		return 1;
	}
	if( fread(&caplen,1,sizeof(u_int16_t),trazas->interfaces[indice].trazaAbierta.fh)!=sizeof(u_int16_t)){ 
		fprintf(trazas->fileForError, "Error al leer el caplen del fichero %s del interfaz %d - Posicion: %llu", trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1], (indice-1),(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
		return 0;
	}
	if( fread(&len,1,sizeof(u_int16_t),trazas->interfaces[indice].trazaAbierta.fh)!=sizeof(u_int16_t)){ 
		fprintf(trazas->fileForError, "Error al leer el len del fichero %s del interfaz %d - Posicion: %llu", trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1], (indice-1),(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
		return 0;
	}
	
	if( caplen > MAX_PACKET_LEN ){
		fprintf(trazas->fileForError, "La longitud del paquete (%d) supera los limites (%d). En el fichero %s - Posicion: %llu \n", caplen, MAX_PACKET_LEN,trazas->interfaces[indice].ficheros[trazas->interfaces[indice].numficheroParaAbrir-1],(unsigned long long)ftello(trazas->interfaces[indice].trazaAbierta.fh));
		return 0;
	}
	
	if( caplen > 0 ){
		//rellenar el NDLTpkthdr
		trazas->interfaces[indice].pkthdr.caplen=caplen;
		trazas->interfaces[indice].pkthdr.len=len;
		trazas->interfaces[indice].pkthdr.ts.tv_sec=secs;
		trazas->interfaces[indice].pkthdr.ts.tv_nsec=nsecs;
		
		// leer el paquete
		if (fread(trazas->interfaces[indice].packet.buffer, 1, caplen, trazas->interfaces[indice].trazaAbierta.fh) != caplen) {
			fprintf(trazas->fileForError, "Error leyendo %u bytes\n", caplen);
                        return 0;
		}
	} else{ 
		fprintf(trazas->fileForError, "Warning: caplen=0 !!\n");
		trazas->numPacketsDiscarded++;    
		
		if(trazas->filePacketsToDiscard!=NULL && checkPacketInFile(trazas)==-1) return(-1);
		return 0;
	}
	return 2;
}

//lee un paquete pcap del interfaz que indique el el parámetro 'indice'. Devuelve 1 si hay exito o 0 su se ha producido algún error al leer el siguiente paquete pcap, por ejemplo que se haya acabado el fichero.
static int leerPaquetePcap(NDLTdata_t *trazas,int indice){
	struct pcap_pkthdr *hdr;
	if(pcap_next_ex(trazas->interfaces[indice].trazaAbierta.ph, &hdr, &trazas->interfaces[indice].packet.pkt)!=-2){
		//adaptar el struct pcap_pkthdr a un NDLTpkthdr
		trazas->interfaces[indice].pkthdr.caplen=hdr->caplen;
		trazas->interfaces[indice].pkthdr.len=hdr->len;
		trazas->interfaces[indice].pkthdr.ts.tv_sec=hdr->ts.tv_sec;
		trazas->interfaces[indice].pkthdr.ts.tv_nsec=hdr->ts.tv_usec*1000;
		return 1;
	}else return 0;
}

/*
Función que abre el primer fichero de todas las interfaces o el fichero si se trata de una traza directamente.
Devuelve 1 en caso de éxito y 0 en caso de error (que no se pueda abrir algún fichero)
*/
static int NDLTopen_next_multiple(NDLTdata_t *data, char *errbuf) {
	char errbufPcap[PCAP_ERRBUF_SIZE];
	if (data->multiFile) {
		//abrimos el primer fichero de cada interfaz
		for(int i=0;i<data->numInterfaces;i++){
			if (data->fileFormato == NDLTFORMAT_PCAP) {
				pcap_t *pcap = pcap_open_offline(data->interfaces[i].ficheros[data->interfaces[i].numficheroParaAbrir], errbufPcap);
				if(!pcap){
					if (errbuf) sprintf(errbuf, "Error al abrir el fichero %s - %s\n", data->interfaces[i].ficheros[data->interfaces[i].numficheroParaAbrir],errbufPcap);
					return 0;
				}
				data->interfaces[i].trazaAbierta.ph = pcap;
				//leer primer paquete de cada fichero y guardalo
				leerPaquetePcap(data,i);
			}
			else if (data->fileFormato == NDLTFORMAT_DRIV){
				data->interfaces[i].trazaAbierta.fh=fopen(data->interfaces[i].ficheros[data->interfaces[i].numficheroParaAbrir],"r");
				if(!data->interfaces[i].trazaAbierta.fh && errbuf){ 
					sprintf(errbuf, "Error: no se pudo abrir el fichero %s", data->interfaces[i].ficheros[data->interfaces[i].numficheroParaAbrir]);
					return 0;
				}
				
				if(leerPaqueteFile(data,i)==0) return 0;
			}
			data->interfaces[i].numficheroParaAbrir++;
		}
	}else{
		//abro el fichero con la traza
		if (data->fileFormato == NDLTFORMAT_PCAP) {
			pcap_t *pcap = pcap_open_offline(data->path, errbufPcap);
			if (!pcap) {
				if (errbuf) sprintf(errbuf, "Error al abrir el fichero %s - %s\n", data->path,errbufPcap);
				return 0;
			}
			data->traceFile.ph = pcap;
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
	
	struct stat buf;
	//Si el fichero es un file of files se van a guardar los paths de los ficheros en un arrays de estructuras. Una estructura por interfaz que se vea (interfaces separadas por una línea en blanco)
	if(nuevo->multiFile){
		char aux[TAM_LINE];
		int lineaVacia=1;  //flag que va a indicar si en la línea anterior se ha visto una línea en blanco (para crear una neuva estrutura). Se inicializa a 1 para crear la primera estructura (se supone que el fichero comienza sin líneas en blanco)
		while(!feof(fileOfPaths)){
	 		if(fgets(aux,TAM_LINE,fileOfPaths)!=NULL){ 
	 			if(lineaVacia && strlen(aux)>1){
	 				//Se ha visto una línea en blanco (en la línea anterior) y la línea actúal tiene contenido (por si hay más de una línea en blanco de separación)
	 				//creo una nueva esctructura y la inicializo
	 				lineaVacia=0;
	 				nuevo->numInterfaces++;
	 				nuevo->interfaces=realloc(nuevo->interfaces,nuevo->numInterfaces*sizeof(struct interfaces_t));
	 				nuevo->interfaces[nuevo->numInterfaces-1].numFicheros=1;
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
	 			 	else{  //sino es una línea en blanco y en la línea anterior no hay blancos significa que el interfaz tiene más ficheros. Se añade el fichero a la estructura ya creada para ese interfaz
	 					lineaVacia=0;
	 					if(nuevo->interfaces[nuevo->numInterfaces-1].numFicheros>=NUM_FICH_INTERFACE){
	 						if (errbuf) sprintf(errbuf, "Error: Demasiados ficheros en la interfaz. Aumente manualmente la constante NUM_FICH_INTERFACE de la librería NDLT");
							return NULL;
	 					}
	 					nuevo->interfaces[nuevo->numInterfaces-1].numFicheros++;
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
	 	free(nuevo);
		return NULL;
	 }
	
	 /*
	// Abro el primer fichero
	if (NDLTopen_next(nuevo, errbuf) != 1) { // Error, deshago lo hecho
		free(nuevo);
		return NULL;
	}*/
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
	}else if(nuevo->fileFormato == NDLTFORMAT_DRIV){
		nuevo->traceFile.fh=fopen(nuevo->path, "w");
		if (!nuevo->traceFile.fh) sprintf(errbuf, "Error: no se pudo abrir el fichero de salida %s", nuevo->path);
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
Devuelve 1 en caso de exito o -1 si se ha producido algún error en la función checkPacketInFile(), por ejemplo que el fichero de descartes no esté ordenado.
*/
static int loop_aux(NDLTdata_t *trazas,struct NDLTpkthdr pkthdr,const u_char *packet,packet_handler callback, u_char *user){
	int codigoResult;
	
	//llamar al callback si se cumplen una serie de cosas. Si se está saltando a un paquete se llama al callback
	if(trazas->jumpPacketActivated){ 
		if(checkPacketInFile(trazas)==-1) return(-1);
               	callback(user, &pkthdr, packet);
        }else{
                //si se ha acabado de saltar. Se comprueba el filtro
                if(trazas->pcapFilterString!=NULL){
                	if(NDLTfilter(&trazas->filtroPcapCompilado, &pkthdr, packet)){
                		//Si pasa el filtro se comprueba si hay paquetes a descartar
                		if(trazas->filePacketsToDiscard!=NULL){
                			//Si hay paquetes a descartar se comprueba si el paquete actual hay que descartarlo
                			codigoResult=checkPacketInFile(trazas);
                			if(codigoResult==-1) return(-1);
                			else if(codigoResult==0) callback(user, &pkthdr, packet); //No se descarta
                			else trazas->numPacketsDiscarded++;  //se aumenta el contador de descartados					 
                		}
                		//si no hay paquetes a descartar se llama al callback
                		else callback(user, &pkthdr, packet);
                	}else{
                		trazas->numPacketsDiscarded++;
                		if(checkPacketInFile(trazas)==-1) return(-1); //miramos a ver si ese paquete se descarta para leer el siguiente
                	}
                }else{			
                	//si no se ha pasado filtro se comprueba si se ha pasado paquetes a descartar
                	if(trazas->filePacketsToDiscard!=NULL){
                		//Si hay paquetes a descartar se comprueba si el paquete actual hay que descartarlo
                		codigoResult=checkPacketInFile(trazas);
                		if(codigoResult==-1) return(-1);
                		else if(codigoResult==0) callback(user, &pkthdr, packet);
                		else trazas->numPacketsDiscarded++; //se aumenta el contador de descartados				 
                	}
                	//si no hay paquetes a descartar se llama al callback
                	else callback(user, &pkthdr, packet);
                }
      }			
      return 1;
}

/*
Función interna que comprueba si se han acabdo de leer todos los ficheros de todas las interfaces.
Si es 0 aun no hemos acabado de leer todos los ficheros. Si es 1 todos los ficheros de todas las interfaces han sido leidos.
*/
static int checkFin(NDLTdata_t *trazas){
	for(int i=0;i<trazas->numInterfaces;i++){
		if(trazas->interfaces[i].leidosTodos!=1) return 0;
	}
	return 1;
}

//Devuelve 1 en éxito y otros valores en caso de error
int NDLTloop(NDLTdata_t *trazas, packet_handler callback, u_char *user) {
	unsigned char buf[MAX_PACKET_LEN];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *hdr;
	const u_char *packet;
	u_int32_t secs,nsecs;
	u_int16_t len,caplen;
	struct NDLTpkthdr pkthdr;
	unsigned long long  posALeerDeFichero = 0;
	unsigned long long  nuevaPosALeerDeFichero = 0;
	//int retNDLTopenNext,codigoResult;
	int i;
	int numInterfazElegido=0, resultado;
	long double ts,tsMinimo=0;
	
	// Se supone que el fichero, o el primero de ellos, está ya abierto
	// Esto permite por ejemplo llamar a NDLTjumpToPacket() y después a NDLTloop()
	// Si hiciéramos aquí un while(NDLTopen_next()) nos cargaríamos lo que hubiera hecho antes un NDLTjumpToPacket()
	while (1) {
		if(trazas->multiFile){
			//Comprobar si para todos los interfaces esta variable esta a 1 y si es asi salir del bucle infinito
			if(checkFin(trazas)) break;
			
			//elijo el primer paquete que vea como minimo (del primer interfaz que tenga el fichero abierto, es decir, la variable leidosTodos a 0)
			for(i=0;i<trazas->numInterfaces;i++){  
				if(!trazas->interfaces[i].leidosTodos){
					tsMinimo = trazas->interfaces[i].pkthdr.ts.tv_sec+trazas->interfaces[i].pkthdr.ts.tv_nsec/1000000000.0L;
					numInterfazElegido=i;
					break;
				}
			}
			//comprobar cual es el paquete con menor timestamp de los de los interfaces y guardar el número del interfaz en 'numInterfazElegido'
			for(i=0;i<trazas->numInterfaces;i++){
				ts=trazas->interfaces[i].pkthdr.ts.tv_sec+trazas->interfaces[i].pkthdr.ts.tv_nsec/1000000000.0L;
				if(!trazas->interfaces[i].leidosTodos && ts<tsMinimo){
					tsMinimo=ts;
					numInterfazElegido=i;
				}
			}
		}
		
		if (trazas->fileFormato==NDLTFORMAT_PCAP){ //si la traza es pcap
			if(trazas->multiFile){
				trazas->numPktsLeidos++;
				
				// Incrementar el contador de bytes que se han leido
                		
                		nuevaPosALeerDeFichero = (unsigned long long)ftello(pcap_file(trazas->interfaces[numInterfazElegido].trazaAbierta.ph));
                		if (nuevaPosALeerDeFichero > trazas->interfaces[numInterfazElegido].posALeerDeFichero) trazas->bytesTotalesLeidos += nuevaPosALeerDeFichero - trazas->interfaces[numInterfazElegido].posALeerDeFichero;
                		//if (nuevaPosALeerDeFichero > posALeerDeFichero) trazas->bytesTotalesLeidos += nuevaPosALeerDeFichero - posALeerDeFichero;
                		else trazas->bytesTotalesLeidos += nuevaPosALeerDeFichero;
                		
                		//posALeerDeFichero = nuevaPosALeerDeFichero;
                		trazas->interfaces[numInterfazElegido].posALeerDeFichero=nuevaPosALeerDeFichero;
                		//llamar a la función que llamará al callback del usuario
                		resultado=loop_aux(trazas,trazas->interfaces[numInterfazElegido].pkthdr,trazas->interfaces[numInterfazElegido].packet.pkt,callback,user);
                		
                		if(resultado!=1) return resultado;
                		// actualizar la posicion de paquete con la del siguiente
      				//trazas->posThisPacket = (unsigned long long)ftello(NDLTfile(trazas));
      				trazas->interfaces[numInterfazElegido].posThisPacket = (unsigned long long)ftello(pcap_file(trazas->interfaces[numInterfazElegido].trazaAbierta.ph));
      				
      				//se va a leer el siguiente paquete del interfaz que ha sido elegido con menor timestamp
				if(!leerPaquetePcap(trazas,numInterfazElegido)){
					//abrir el siguiente fichero, si hay mas ficheros disponibles
					if(trazas->interfaces[numInterfazElegido].numficheroParaAbrir < trazas->interfaces[numInterfazElegido].numFicheros){
						pcap_close(trazas->interfaces[numInterfazElegido].trazaAbierta.ph);
						pcap_t *pcap = pcap_open_offline(trazas->interfaces[numInterfazElegido].ficheros[trazas->interfaces[numInterfazElegido].numficheroParaAbrir], errbuf);
						if (!pcap) {
							fprintf(trazas->fileForError, "Error: no se pudo abrir el fichero %s. Error: %s\n", trazas->interfaces[numInterfazElegido].ficheros[trazas->interfaces[numInterfazElegido].numficheroParaAbrir],errbuf);
							return 0;
						}
						trazas->interfaces[numInterfazElegido].trazaAbierta.ph = pcap;
						if(numInterfazElegido==0) trazas->contFiles++;
						trazas->interfaces[numInterfazElegido].numficheroParaAbrir++;
						leerPaquetePcap(trazas,numInterfazElegido);
					}else{  //ya se han abierto todos los ficheros de ese interfaz
						trazas->interfaces[numInterfazElegido].leidosTodos=1;
					}
				}
      				if (trazas->shouldBreakLoopFlag) {
             				trazas->shouldBreakLoopFlag = 0;
             				trazas->jumpPacketActivated=0;
             				return 1;
      				}
			}
			else{
				while (pcap_next_ex(trazas->traceFile.ph, &hdr, &packet)!=-2) {
					trazas->numPktsLeidos++;
					//adaptar el struct pcap_pkthdr a un NDLTpkthdr
					pkthdr.caplen=hdr->caplen;
					pkthdr.len=hdr->len;
					pkthdr.ts.tv_sec=hdr->ts.tv_sec;
					pkthdr.ts.tv_nsec=hdr->ts.tv_usec*1000;
                
               				// Incrementar el contador de bytes que se han leido
                			nuevaPosALeerDeFichero = (unsigned long long)ftello(NDLTfile(trazas));
                			if (nuevaPosALeerDeFichero > posALeerDeFichero) trazas->bytesTotalesLeidos += nuevaPosALeerDeFichero - posALeerDeFichero;
                			else trazas->bytesTotalesLeidos += nuevaPosALeerDeFichero;
                			posALeerDeFichero = nuevaPosALeerDeFichero;
                		
                			resultado=loop_aux(trazas,pkthdr,packet,callback,user);
                			if(resultado!=1){ 
                				return resultado;
                			}
                			 // actualizar la posicion de paquete con la del siguiente
      					trazas->posThisPacket = (unsigned long long)ftello(NDLTfile(trazas));
      					if (trazas->shouldBreakLoopFlag) {
             					trazas->shouldBreakLoopFlag = 0;
             					trazas->jumpPacketActivated=0;
             					return 1;
      					}
                		}
                		break;
			}
		} else if (trazas->fileFormato==NDLTFORMAT_DRIV) {  //si la traza es driv
			if(trazas->multiFile){
				trazas->numPktsLeidos++;
                		trazas->bytesTotalesLeidos += 2*sizeof(u_int32_t)+ 2*sizeof(u_int16_t); // Incrementar el contador de bytes que se han leido
				trazas->bytesTotalesLeidos += trazas->interfaces[numInterfazElegido].pkthdr.caplen;  // Incrementar el contador de bytes que se han leido
                    		resultado=loop_aux(trazas,trazas->interfaces[numInterfazElegido].pkthdr,trazas->interfaces[numInterfazElegido].packet.buffer,callback,user);
                    		if(resultado!=1) return resultado;
                    		
                    		//leer otro paquete del interfaz que ha sido seleccionado
				resultado=leerPaqueteFile(trazas,numInterfazElegido);
				if(resultado==0) return -1;
				
				//COMPROBAR SI SE HA ACABADO EL FICHERO PARA ABRIR EL SIGUIENTE DEL INTERFAZ o SE HA PRODUCIDO UN ERROR DE LECTURA EN ESE FICHERO Y CAMBIAMOS A OTRO
				if(feof(trazas->interfaces[numInterfazElegido].trazaAbierta.fh) || resultado==1){
					if(trazas->interfaces[numInterfazElegido].numficheroParaAbrir<trazas->interfaces[numInterfazElegido].numFicheros){
						//abrir el siguiente fichero
						fclose(trazas->interfaces[numInterfazElegido].trazaAbierta.fh);
						trazas->interfaces[numInterfazElegido].trazaAbierta.fh=fopen(trazas->interfaces[numInterfazElegido].ficheros[trazas->interfaces[numInterfazElegido].numficheroParaAbrir],"r");
						if(!trazas->interfaces[numInterfazElegido].trazaAbierta.fh){ 
							fprintf(trazas->fileForError, "Error: no se pudo abrir el fichero %s\n", trazas->interfaces[numInterfazElegido].ficheros[trazas->interfaces[numInterfazElegido].numficheroParaAbrir]);
							return 0;
						}
						
						if(numInterfazElegido==0) trazas->contFiles++;
						trazas->interfaces[numInterfazElegido].numficheroParaAbrir++;
						
						//leer el primer paquete
						resultado=leerPaqueteFile(trazas,numInterfazElegido);
							
						if(resultado==0) return -1;
					}else{  //ya se han abierto todos los ficheros de ese interfaz
						trazas->interfaces[numInterfazElegido].leidosTodos=1;
					}
				}
                    		
                    		// actualizar la posicion de paquete con la del siguiente
                		//trazas->posThisPacket = (unsigned long long)ftello(NDLTfile(trazas));
                		trazas->interfaces[numInterfazElegido].posThisPacket = (unsigned long long)ftello(trazas->interfaces[numInterfazElegido].trazaAbierta.fh);
                		if (trazas->shouldBreakLoopFlag) {
                    			trazas->shouldBreakLoopFlag = 0;
                    			trazas->jumpPacketActivated=0;
                    			return 1;
                		}
			}else{
				while (!feof(trazas->traceFile.fh)) {
					//leer la estructura de tiempo y la estructura de size
					if( fread(&secs,1,sizeof(u_int32_t),trazas->traceFile.fh)!=sizeof(u_int32_t)) break;
					if( fread(&nsecs,1,sizeof(u_int32_t),trazas->traceFile.fh)!=sizeof(u_int32_t)) break;
					if( (secs==0) && (nsecs==0)) break;
					if( fread(&caplen,1,sizeof(u_int16_t),trazas->traceFile.fh)!=sizeof(u_int16_t)) break;
					if( fread(&len,1,sizeof(u_int16_t),trazas->traceFile.fh)!=sizeof(u_int16_t)) break;
					if( caplen > MAX_PACKET_LEN ){
						fprintf(trazas->fileForError, "La longitud del paquete (%d) supera los limites (%d)\n", caplen, MAX_PACKET_LEN);
						//si falla en el primer paquete puede ser porque el fichero sea un fichero de ficheros
						if(trazas->numPktsLeidos==0) fprintf(trazas->fileForError, "Compruebe que el fichero no es un fichero de ficheros.\n");
						return (-1);
					}
					trazas->numPktsLeidos++;
                			trazas->bytesTotalesLeidos += 2*sizeof(u_int32_t)+ 2*sizeof(u_int16_t); // Incrementar el contador de bytes que se han leido
               
					if( caplen > 0 ){
						//rellenar el NDLTpkthdr
						pkthdr.caplen=caplen;
						pkthdr.len=len;
						pkthdr.ts.tv_sec=secs;
						pkthdr.ts.tv_nsec=nsecs;
						// leer el paquete
						if (fread(buf, 1, caplen, trazas->traceFile.fh) != caplen) {
                        				fprintf(trazas->fileForError, "Error leyendo %u bytes\n", caplen);
                        				return(-1);
                    				}
                    				trazas->bytesTotalesLeidos += caplen;  // Incrementar el contador de bytes que se han leido
                    				resultado=loop_aux(trazas,pkthdr,buf,callback,user);
                    				if(resultado!=1) return resultado;
					} else{ 
						fprintf(trazas->fileForError, "Warning: caplen=0 !!\n");
						trazas->numPacketsDiscarded++;    
						if(checkPacketInFile(trazas)==-1) return(-1);
					}
                			
                			// actualizar la posicion de paquete con la del siguiente
                			trazas->posThisPacket = (unsigned long long)ftello(NDLTfile(trazas));
                			if (trazas->shouldBreakLoopFlag) {
                    				trazas->shouldBreakLoopFlag = 0;
                    				trazas->jumpPacketActivated=0;
                    				return 1;
                			}
				}
				break;
			}
		}
        	//trazas->posThisPacket = 0;
	}
	return 1;
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

