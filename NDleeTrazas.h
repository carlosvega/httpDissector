
//
//  NDleeTrazas.h
//  
//
//
//

#ifndef _NDleeTrazas_h
#define _NDleeTrazas_h

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#define NDLT_VERSION    "2.0.2"

#include <time.h>
#include <stdio.h>
#include <pcap.h>

// Formatos de trazas
#define NDLTFORMAT_PCAP_STR "pcap"
#define NDLTFORMAT_DRIV_STR "raw"

#define TAM_LINE 	1000

typedef struct NDLTdata NDLTdata_t;
typedef struct NDLTdataEscritura NDLTdataEscritura_t;

struct NDLTpkthdr {
    struct timespec ts;
    unsigned int    caplen;
    unsigned int   len;
};

union descriptores 
{
	FILE 		*fh;    //file handle  (usado para abrir el fichero raw para leer o escribir la traza)
	pcap_t 		*ph;    //pcap handle  (usado para abrir el pcap para leer la traza)
	pcap_dumper_t 	*pdh;   //pcap dump handler (usado para abrir el pcap en escritura)
};

struct NDLTdata{
	char                path[TAM_LINE];  		// nombre del fichero de trazas, o del fichero de paths de trazas
	FILE                *fileOfPaths;		// fichero de paths
	int                 fileFormato;  		// NDLTFORMAT_PCAP si la traza es pcap, NDLTFORMAT_DRIV si la traza es raw
	int                 multiFile; 			// 1 si se trata de múltiples ficheros, 0 en caso contrario
	char                *pcapFilterString;		// cadena con filtro pcap a aplicar
	struct bpf_program  filtroPcapCompilado; 	// filtro compilado
	union descriptores  traceFile;              	// fichero de traza abierto
	int                 contFiles;  		// contador que indica el número de fichero en el que se está, empezando en 1. (En el caso de que se pase el fichero de trazas este contador será 1 en cuanto se empiece a leer).
	unsigned long long  bytesTotalesLeidos;     	// Numero total de bytes leidos entre todos los ficheros de la traza
	unsigned long long  bytesTotalesFicheros;	// numero total de bytes de los ficheros
	
	unsigned long long  posThisPacket;          	// posición en bytes en el fichero actual del comienzo del paquete que se acaba de leer. Es diferente de la posición de lectura en el fichero, que sería la del siguiente paquete
	FILE                *fileIndex;             	// Fichero con indices
	int                 maxIndicesCreados;      	// Número máximo de indices para los que hay reservada memoria en indices
	int                 numIndicesLeidos;       	// Cantidad de elementos que hay usados en indices
	struct NDLTindexElement *indices;           	// Array de elementos de indice
	int                 shouldBreakLoopFlag;    	// Lo pone a 1 NDLTbreakloop() para avisar a NDLTloop() que debe terminar
	unsigned long long  numPktsLeidos;          	// Numero de paquetes leidos hasta el momento en toda la traza
	
	int		    jumpPacketActivated;  	// Si está a 1 indica que se ha pedido saltar a un paquete en concreto. 
	unsigned long long  numPacketsDiscarded;	// número de paquetes descartados hasta el momento (tanto por paquetes descartados como por paquetes que no pasen el filtro)
	unsigned long long  nextPacketToDiscard; 	//numero del siguiente paquete a descartar (se van leyendo del fichero de paquetes a descartar)
	FILE 		*filePacketsToDiscard;		// handle del fichero con los paquetes a descartar (paquetes duplicados)
	//int		errorToStdErr;			// Flag que si es 1 los errores de NDLTloop se vuelvan por stderr, y si es 0 no se vuelvan. 
	FILE		*fileForError;			// Apuntador de fichero donde irán los errores. Por defecto está a stderr
	
	struct interfaces_t 	*interfaces; 		// array de estructuras 'struct interfaces_t' (una estructura para cada interfaz que haya en el fichero de entrada. Las interfaces vienen separadas por una línea en blanco)
	int 			numInterfaces;		// contador de interfaces
};

	struct NDLTdataEscritura{
	char    		path[TAM_LINE];
	union descriptores  	traceFile;		// fichero de traza abierto			
	int     		fileFormato;  		// NDLTFORMAT_PCAP si el fichero de salida es pcap, NDLTFORMAT_DRIV si es raw	
	int 			displayOutput;		// 1 si se muestran los paquetes por pantalla. 0 si se guardan a archivo 
	unsigned int		snaplen;		// bytes que se quieren sacar del paquete.
};

// user : datos de usuario indicados en NDLTloop()
// h : informacion sobre el paquete
// bytes : zona de memoria con el paquete
typedef void (*packet_handler)(u_char *user, const struct NDLTpkthdr *h, const u_char *bytes);


/* Abrir traza o lista de trazas para lectura. Comprueba que los parámetros sean correctos y crea una estructura NDLTdata_t con esos parámetros.
Parámetros:
 	path : cadena con el path al fichero de traza o fichero con lista de paths a ficheros de trazas
 	format : cadena que vale NDLTFORMAT_PCAP_STR si el/los ficheros de trazas estan en formato pcap. NDLTFORMAT_DRIV_STR si esta en el formato raw del driver 10G
 	filter : cadena con el filtro bpf a aplicar a todos los ficheros de traza. 
 	multi : vale 1 para indicar que path es un fichero con listas de ficheros, si vale 0 entonces path es el fichero de traza
 	errbuf : si se da un error devuelve NULL y errbuf se rellena con un mensaje de error. Se supone que errbuf tiene espacio para al menos PCAP_ERRBUF_SIZE bytes.
Devuelve la estructura NDLTdata_t creada o NULL en caso de error.
*/
NDLTdata_t *NDLTabrirTraza(char *path, char *format, char *filter, int multi, char *errbuf);


/* Abrir un fichero para escritura. Función que comprueba que los parámetros sean correctos y crea una estructura NDLTdataEscritura_t con esos parámetros.
Parámetros:
	- pathOutput: cadena con el path al fichero en el que se escribirán los paquetes.
	- formatOutput: formato del fichero de salida. NDLTFORMAT_PCAP_STR para formato pcap. NDLTFORMAT_DRIV_STR para formato raw del driver 10G.
	- displayOutput: vale 1 si se escribe por pantalla en vez de a fichero
	- snaplen: Bytes del paquete que el usuario quiere escribir
	- errbuf : si se da un error devuelve NULL y errbuf se rellena con un mensaje de error. Se supone que errbuf tiene espacio para al menos PCAP_ERRBUF_SIZE bytes.
Devuelve la estructura NDLTdataEscritura_t creada o NULL en caso de error.
*/
NDLTdataEscritura_t *NDLTabrirTrazaEscritura(char *pathOutput,char *formatOutput, int displayOutput,unsigned int snaplen,char *errbuf);


/* Función que abre el fichero que permite descartar paquetes a la hora de procesar. 
Parámetros:
	- trazas : Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
	- pathFile: Cadena con el path que contiene los números de paquetes a descartas. El fichero debe estar ordenado.
	- errbuf: si se produce un error errbuf se rellena con un mensaje de error. Se supone que errbuf tiene espacio para al menos PCAP_ERRBUF_SIZE bytes.
Devuelve 1 si éxito, 0 si error.
*/
int NDLTopenFileDiscards(NDLTdata_t *trazas,char *pathFile,char *errbuf);


/* Función que indica por donde salen los mensajes de error del programa (por ejemplo de la función NDLTloop). Si no se usa la función, por defecto, los mensajes de error salen por stderr.
Parámetros:
	- trazas : Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
	- outputStderr : Descriptor de fichero donde irán los mensajes de error.
Devuelve 1 en caso de éxito, 0 en caso de que la estructura NDLTdata_t no exista
*/
int setErrorOutput(NDLTdata_t *trazas,FILE *outputStderr);


/* Función que procesa todos los paquetes de la traza/s
Parámetros:
	- trazas : Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
	- callback : funcion a la que se llama para cada paquete leido
	- user : datos de usuario que se pasan al callback
Devuelve 1 en caso de éxito y otros valores en caso de error
*/
int NDLTloop(NDLTdata_t *trazas, packet_handler callback, u_char *user);


/* Función que cierra todos los elementos abiertos, como el pcap_t en caso de que las trazas sean pcap, o el descriptor de fichero. Tambien libera el registro de indices.
Parámetros:
	- trazas : Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
No devuelve nada.
*/
void NDLTclose(NDLTdata_t *trazas);


/* Función que cierra todos los elementos abiertos de escritura, como el pcap_dumper en caso de que las trazas sean pcap, o el descriptor de fichero.
Parámetros:
	- trazas : Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
No devuelve nada.
*/
void NDLTcloseEscritura(NDLTdataEscritura_t *trazas);


// Función que devuelve el FILE * del fichero que se está procesando en ese momento
FILE *NDLTfile(NDLTdata_t *trazas);

// Función que devuelve el número de archivo que se está procesando en ese momento. Cuenta desde 1
int NDLTfileNumber(NDLTdata_t *trazas);

// Función que devuelve el tamaño del archivo que se está procesando en ese momento
unsigned long long NDLTfileSize(NDLTdata_t *trazas);


/*Función que devuelve el número de paquetes descartados de la traza o trazas.
Parámetros:
	- trazas : Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
Devuelve el número de paquetes descartados.
*/
unsigned long long NDLTpacketsDiscarded(NDLTdata_t *trazas);


// Función que devuelve el número de bytes totales leídos de todos los ficheros de la traza. Si los ficheros tienen algun tipo de tail no lo tiene en cuenta. Si se hace un NDLTjumpToPacket() se reinicia
unsigned long long NDLTbytesRead(NDLTdata_t *trazas);


// Función que devuelve el número de bytes totales de todos los ficheros de la traza (el tamaño total de todos los ficheros, o del fichero de traza en caso de ser solo uno)
unsigned long long NDLTtotalBytes(NDLTdata_t *trazas);

// Función que devuelve la posición en bytes en el fichero actual del comienzo del paquete que se acaba de leer. Es diferente de la posición de lectura en el fichero, que sería la del siguiente paquete
unsigned long long NDLTposThisPacket(NDLTdata_t *trazas);


/* Funcion para especificar el fichero de indices en caso de existir. 
Parámetros:
	- trazas : Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
	- indexFilePath : Cadena con el path del fichero de índices.
Devuelve 1 si exito, 0 si error (por ejemplo al abrir ese fichero de indices)
*/
int NDLTsetIndexFile(NDLTdata_t *trazas, char *indexFilePath);


/* Salta en la lectura al paquete que se le indica. Se cuentan desde el 1. 
Parámetros:
	- trazas : Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
	- pktNumber : Número de paquete al que se va a saltar
Devuelve 0 si error, 1 si exito
*/
int NDLTjumpToPacket(NDLTdata_t *trazas, unsigned long long pktNumber);


// Equivalente a pcap_breakloop(), sirve para activar un flag que hace que se salga de NDLTloop()
void NDLTbreakloop(NDLTdata_t *trazas);


/* Función que escribe en un fichero (o salida estándar) un paquete. Equivalente a pcap_dump.
Parámetros:
	- trazas: resultado de un NDLTabrirTrazaEscritura(), donde habrá un campo con el apuntador del fichero donde se va a guardar la traza. 
	- h: los datos de la cabecera del paquete que serán escritos en el fichero
	- sp: Datos del paquete que serán escritos en el fichero
No devuelve nada.
*/
void NDLTdump(NDLTdataEscritura_t *trazas, const struct NDLTpkthdr *h, const u_char *sp);


/*
 * Función que compila un filtr BPF. Es un wrapper para pcap_compile_nopcap. Tiene unos requerimientos especiales (el resto de parámetros, igual que en pcap_compile). Se usa para poder filtrar por n filtros, ya que NDLTloop solo permite filtrar por uno solo:
 * 
 * - snaplen: si es una captura en RAW, hay que saber qué snaplen se ha puesto y meterlo a mano.
 * - linktype: lo mismo. Se pueden utilizar los de PCAP (DLT_<algo>). Ej: DLT_EN10MB para ethernet.
 * 
 *  Devuelve 0 si no hay error.
 */
int NDLTcompile(int snaplen_arg, int linktype_arg, struct bpf_program *program, const char *buf, int optimize, bpf_u_int32 mask);

// Dado un paquete, se aplica el filtro BPF. Devuelve 0 si el paquete no pasa el filtro y distinto de 0 en caso contrario.
int NDLTfilter(struct bpf_program *fp, const struct NDLTpkthdr *h, const u_char *pkt);

// Wrapper para pcap_freecode. Libera memoria de un filtro BPF.
void NDLTfreecode(struct bpf_program *fp);

// Devuelve el numero de paquete en las trazas del ultimo leido
unsigned long long NDLTpktNumber(NDLTdata_t *trazas);


#endif

/*
 Version history
    1.0     :   Version inicial
    1.1     :   Incluidas NDLTbytesRead(), NDLTposThisPacket(), NDLTsetIndexFile() y NDLTjumpToPacket()
                Modificado NDLTloop() y NDLTabrirTraza() para ser compatibles con NDLTjumpToPacket()
                Incluida NDLTbreakloop()
    1.2	    :   Incluidas NDLTcompile(), NDLTfilter() y NDLTfreecode()
    1.3	    :   Incluidas NDLTopenFileDiscards() y NDLTpacketsDiscarded().
    		Modificado NDLTloop() y NDLTabrirTraza().
    1.4     :   Incluida NDLTpktNumber()
    2.0	    :   Añadida nueva funcionalidad que permite procesar paquetes de ficheros de traza de varias interfaces paralelamente.
    2.0.1   :   Pequeños cambios para que no de warning con -pedantic y -stc=c99
    2.0.2   :   Arreglado fallo al descartar el último paquete del fichero de descartes
    TODO : que el jump pueda saltar a un timestamp en vez de a un numero de paquete
*/


