
/** @file NDleeTrazas.h
* \brief Esta librería permite la apertura, lectura y escritura de ficheros de trazas de distintos formatos (actualmente pcap y raw). 
*
* Permite la entrada tanto de un path de un fichero de trazas directamente o un path de un fichero que contiene una lista de paths de los ficheros de trazas. En este último caso el fichero puede contener paths de trazas de distintas interfaces, debiendo ser su formato de esta manera:
* Cada interfaz estará separado por una línea en blanco. En cada interfaz los paths se separarán por un salto de línea. Por ejemplo: suponer que hay tres interfaces y cada uno de ellos tiene 2 ficheros de trazas, el fichero será así:
*  \code   
	INTERFACE1_PATHFILE1
	INTERFACE1_PATHFILE2
	
	INTERFACE2_PATHFILE1
	INTERFACE2_PATHFILE2
	
	INTERFACE3_PATHFILE1
	INTERFACE3_PATHFILE2
*  \endcode
*  Para el caso en el que solo haya un interfaz, el fichero consistirá en una lista de paths separados por saltos de línea.
*  \author Olga Esquiroz
*  \version ver NDLT_VERSION
*  
* Se puede ver un ejemplo de uso de esta librería en el siguiente fichero: \include doc/ejemplos/ejemploUso_NDLT.c
*/

#ifndef _NDleeTrazas_h
#define _NDleeTrazas_h

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#define NDLT_VERSION    "2.2"

#include <time.h>
#include <stdio.h>
#include <pcap.h>

// Formatos de trazas
#define NDLTFORMAT_PCAP_STR "pcap"
#define NDLTFORMAT_DRIV_STR "raw"

#define TAM_LINE 	1000
#define MAX_PACKET_LEN 	65535

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
	
	int			nextPacketActive;  //Si se ha llamado a la función NDLTnext().
	struct NDLTpkthdr 	pkthdr_next;		//header a devolver si se llama a NDLTnext()
	u_char			packet_next[MAX_PACKET_LEN];		//paquete a devolver si se llama a NDLTnext()
	//unsigned int 		tamPacket;
	
};

// user : datos de usuario indicados en NDLTloop()
// h : informacion sobre el paquete
// bytes : zona de memoria con el paquete
typedef void (*packet_handler)(u_char *user, const struct NDLTpkthdr *h, const u_char *bytes);


/** \brief Abrir traza o lista de trazas para lectura. Comprueba que los parámetros sean correctos y crea una estructura NDLTdata_t con esos parámetros.
* 	\param path Cadena con el path al fichero de traza o fichero con lista de paths a ficheros de trazas
*	\param format Cadena que vale NDLTFORMAT_PCAP_STR si el/los ficheros de trazas estan en formato pcap. NDLTFORMAT_DRIV_STR si esta en el formato raw del driver 10G
* 	\param filter Cadena con el filtro bpf a aplicar a todos los ficheros de traza. 
* 	\param multi Vale 1 para indicar que path es un fichero con listas de ficheros, si vale 0 entonces path es el fichero de traza
* 	\param errbuf Si se da un error, la funcion devuelve NULL y errbuf se rellena con un mensaje de error en cadena de texto. Se supone que errbuf tiene espacio para al menos PCAP_ERRBUF_SIZE bytes o es NULL y entonces no se rellena.
* \return Devuelve la estructura NDLTdata_t creada o NULL en caso de error. Posibles casos de error:
* - Que no se haya indicado una ruta de un fichero
* - Que haya fallado al abrir el fichero con la lista de paths o al abrir algún fichero de trazas de la lista de paths (en caso de multi a 1) o el fichero de trazas directamente (multi a 0)
* - Que se haya indicado un formato de fichero no soportado o erróneo.
* - Error al crear la estructura NDLTdata_t que se devuelve
*/
NDLTdata_t *NDLTabrirTraza(char *path, char *format, char *filter, int multi, char *errbuf);


/** \brief Abrir un fichero para escritura. Función que comprueba que los parámetros sean correctos y crea una estructura NDLTdataEscritura_t con esos parámetros.
* 	\param pathOutput Cadena con el path al fichero en el que se escribirán los paquetes.
* 	\param formatOutput Formato del fichero de salida. NDLTFORMAT_PCAP_STR para formato pcap. NDLTFORMAT_DRIV_STR para formato raw del driver 10G.
* 	\param displayOutput Vale 1 si se escribe por pantalla en vez de a fichero
* 	\param snaplen Bytes del paquete que el usuario quiere escribir
* 	\param errbuf Si se da un error devuelve NULL y errbuf se rellena con un mensaje de error. Se supone que errbuf tiene espacio para al menos PCAP_ERRBUF_SIZE bytes.
* \return Devuelve la estructura NDLTdataEscritura_t creada o NULL en caso de error. Posibles casos de error:
* - Que no se haya indicado un fichero en el que se escribirá, en el caso de escribir a fichero (displayOutput a 0)
* - Que se haya indicado un formato de fichero de traza no soportado o erróneo.
*/
NDLTdataEscritura_t *NDLTabrirTrazaEscritura(char *pathOutput,char *formatOutput, int displayOutput,unsigned int snaplen,char *errbuf);


/** \brief Función que abre el fichero que permite descartar paquetes a la hora de procesar. 
* 	\param trazas Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* 	\param pathFile Cadena con el path que contiene los números de paquetes a descartas. El fichero debe estar ordenado.
* 	\param errbuf Si se produce un error errbuf se rellena con un mensaje de error. Se supone que errbuf tiene espacio para al menos PCAP_ERRBUF_SIZE bytes.
* \return Devuelve 1 si éxito, 0 si error. Posibles casos de error:
* - Algún error comprobando los parámetros de entrada: que no exista la estructura 'trazas' o que no se haya pasado ningún fichero con paquetes a descartar.
* - Algún error abriendo el fichero con los paquetes a descartar.
* - Que el fichero de descartes esté vacío.
*/
int NDLTopenFileDiscards(NDLTdata_t *trazas,char *pathFile,char *errbuf);


/** \brief Función que indica por donde salen los mensajes de error del programa (por ejemplo de la función NDLTloop). Si no se usa la función, por defecto, los mensajes de error salen por stderr.
* 	\param trazas  Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* 	\param outputStderr  Descriptor de fichero donde irán los mensajes de error.
* \return Devuelve 1 en caso de éxito, 0 en caso de que la estructura NDLTdata_t no exista
*/
int setErrorOutput(NDLTdata_t *trazas,FILE *outputStderr);


/** \brief Función que lee el siguiente paquete de la traza/s y devuelve éxito o error. Equivalente a pcap_next_ex. 
*	\param trazas Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
*	\param h Estructura struct NDLTpkthdr en la que se escribirá la cabecera del siguiente paquete.
*	\param pkt_data Donde se guardará el contenido del siguiente paquete.
* \return Devuelve 1 si se ha leído correctamente el paquete, -1 en caso de error y -2 en caso de que se haya terminado de leer la traza, es decir, no haya más paquetes.
*/
int NDLTnext_ex(NDLTdata_t *trazas, const struct NDLTpkthdr **h,const u_char **pkt_data);


/** \brief Función que devuelve el siguiente paquete de la traza/s. Equivalente a pcap_next. 
*	\param trazas Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
*	\param h Estructura struct NDLTpkthdr en la que se escribirá la cabecera del siguiente paquete.
* \return Devuelve el contenido del siguiente paquete o null si ya no hay más paquetes o se ha producido un error.
*/
const u_char *NDLTnext(NDLTdata_t *trazas, const struct NDLTpkthdr **h);


/** \brief Función que procesa todos los paquetes de la traza/s
* 	\param trazas  Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* 	\param callback  Funcion a la que se llama para cada paquete leido
* 	\param user Datos de usuario que se pasan al callback
* \return Devuelve 1 en caso de éxito y otros valores en caso de error. Posibles casos de error:
* - Que se haya producido algún problema al leer los paquetes a descartar del fichero de descartes, por ejemplo que no esté ordenado. Valor devuelto: -1
* - Error al abrir algún fichero de trazas en caso de que se haya pasado un fichero con una lista de paths de trazas. Valor devuelto: 0
* - Error leyendo algún paquete. Valor devuelto: -1
*/
int NDLTloop(NDLTdata_t *trazas, packet_handler callback, u_char *user);


/** \brief Función que cierra todos los elementos abiertos, como el pcap_t en caso de que las trazas sean pcap, o el descriptor de fichero. Tambien libera el registro de indices.
* 	\param trazas Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return No devuelve nada.
*/
void NDLTclose(NDLTdata_t *trazas);


/** \brief Función que cierra todos los elementos abiertos de escritura, como el pcap_dumper en caso de que las trazas sean pcap, o el descriptor de fichero.
* 	\param trazas Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return No devuelve nada.
*/
void NDLTcloseEscritura(NDLTdataEscritura_t *trazas);


/** \brief  \deprecated Función que devuelve el FILE * del fichero que se está procesando en ese momento.
* 	\param trazas Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return Devuelve el descriptor de fichero que se está procesando en ese momento.
*/
FILE *NDLTfile(NDLTdata_t *trazas);


/** \brief \deprecated Función que devuelve el número de archivo que se está procesando en ese momento. Cuenta desde 1
* 	\param trazas Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return Devuelve el número de archivo que se está procesando en ese momento.
*/
int NDLTfileNumber(NDLTdata_t *trazas);

/** \brief \deprecated Función que devuelve el tamaño del archivo que se está procesando en ese momento.
* 	\param trazas Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return Devuelve el tamaño del archivo que se está procesando en ese momento.
*/
unsigned long long NDLTfileSize(NDLTdata_t *trazas);


/** \brief Función que devuelve el número de paquetes descartados de la traza o lista de trazas.
*	\param trazas Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return Devuelve el número de paquetes descartados.
*/
unsigned long long NDLTpacketsDiscarded(NDLTdata_t *trazas);


/** \brief Función que devuelve el número de bytes totales leídos hasta el momento de todos los ficheros de la traza. Si los ficheros tienen algun tipo de tail no lo tiene en cuenta. Si se hace un NDLTjumpToPacket() se reinicia
*	\param trazas  Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return Devuelve el número de bytes totales leídos hasta el momento.
*/
unsigned long long NDLTbytesRead(NDLTdata_t *trazas);


/** \brief Función que devuelve el número de bytes totales de todos los ficheros de la traza (el tamaño total de todos los ficheros, o del fichero de traza en caso de ser solo uno)
*	\param trazas  Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return Devuelve el número de bytes totales.
*/
unsigned long long NDLTtotalBytes(NDLTdata_t *trazas);

/** \brief Función que devuelve la posición en bytes en el fichero actual del comienzo del paquete que se acaba de leer. Es diferente de la posición de lectura en el fichero, que sería la del siguiente paquete
*	\param trazas  Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return Devuelve la posición en bytes en el fichero actual del comienzo del paquete que se acaba de leer.
*/
unsigned long long NDLTposThisPacket(NDLTdata_t *trazas);


/** \brief Funcion para especificar el fichero de indices en caso de existir. 
*	\param trazas  Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
*	\param indexFilePath  Cadena con el path del fichero de índices.
* \return Devuelve 1 si exito, 0 si error. Posibles casos de error:
* - Que no exista la estructura NDLTdata_t 'trazas'
* - Que no se haya indicado un fichero de índices
* - Que no se pueda abrir el fichero de índices
* - Error al intentar reservar memoria para guardar un índice.
*
*/
int NDLTsetIndexFile(NDLTdata_t *trazas, char *indexFilePath);


/** \brief Salta en la lectura al paquete que se le indica. Se cuentan desde el 1. 
*	\param trazas  Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
*	\param pktNumber  Número de paquete al que se va a saltar
* \return Devuelve 0 si error, 1 si exito. Posibles casos de error:
* - Que pktNumber sea 0
* - Que el fichero de descartes no esté ordenado al ir avanzándolo.
*/
int NDLTjumpToPacket(NDLTdata_t *trazas, unsigned long long pktNumber);


/** \brief Equivalente a pcap_breakloop(), sirve para activar un flag que hace que se salga de NDLTloop()
*	\param trazas  Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return No devuelve nada
*/
void NDLTbreakloop(NDLTdata_t *trazas);


/** \brief Función que escribe en un fichero (o salida estándar) un paquete. Equivalente a pcap_dump. 
*	\param trazas Resultado de un NDLTabrirTrazaEscritura(), donde habrá un campo con el apuntador del fichero donde se va a guardar el paquete. 
*	\param h Datos de la cabecera del paquete que serán escritos en el fichero
*	\param sp Datos del paquete que serán escritos en el fichero
* \return No devuelve nada.
*/
void NDLTdump(NDLTdataEscritura_t *trazas, const struct NDLTpkthdr *h, const u_char *sp);


/** \brief Función que compila un filtro BPF. Es un wrapper para pcap_compile_nopcap. Tiene unos requerimientos especiales (el resto de parámetros, igual que en pcap_compile). Se usa para poder filtrar por n filtros, ya que NDLTloop solo permite filtrar por uno solo.
* \param snaplen_arg Si es una captura en RAW, hay que saber qué snaplen se ha puesto y meterlo a mano.
* \param linktype_arg Lo mismo. Se pueden utilizar los de PCAP (DLT_<algo>). Ej: DLT_EN10MB para ethernet.
* \param program Puntero a una estructura bpf_program donde se guardará el filtro a compilar
* \param buf String que se quiere compilar en un programa filtro.
* \param optimize Si se realiza optimización en el resultado.
* \param mask Máscara de ipV4 de la red en la que se capturan los paquetes. 
*  \return Devuelve 0 si no hay error. Posibles casos de error:
* - Los posibles errores devueltos por pcap_compile_nopcap() de la librería pcap.
*/
int NDLTcompile(int snaplen_arg, int linktype_arg, struct bpf_program *program, const char *buf, int optimize, bpf_u_int32 mask);

/** \brief Dado un paquete, se aplica el filtro BPF. Internamente usa la función bpf_filter()
* \param fp Filtro BPF compilado
* \param h Cabecera del paquete que se va a comprobar.
* \param pkt Datos del paquete que se va a comprobar
* \return Devuelve 0 si el paquete no pasa el filtro y distinto de 0 en caso contrario. Posibles casos de error:
* - Los posibles casos de error devueltos por bpf_filter() de la librería pcap
*/
int NDLTfilter(struct bpf_program *fp, const struct NDLTpkthdr *h, const u_char *pkt);

/** \brief Wrapper para pcap_freecode. Libera memoria de un filtro BPF.
* \param fp Filtro BPF compilado que se quiere liberar.
* \return No devuelve nada.
*/
void NDLTfreecode(struct bpf_program *fp);

/** \brief Devuelve el número de paquete en las trazas del último leído
* \param trazas  Estructura (NDLTdata_t *) devuelta por la función NDLTabrirTraza().
* \return Devuelve el número del último paquete leído.
*/
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
    2.0.3   :   Puestos un par de casts para evitar warnings en Linux (por const en la variable y no en el argumento de un par de funciones)
    2.0.4   :   Añadida comprobación de la existencia del directorio y de salida en NDLTabrirTrazaEscritura().
    2.0.5   :   Modificada la forma de guardar el nombre de los ficheros de cada interfaz. Antes era un array estático, ahora dinámico.
    2.0.6   :   Arreglados fallos de memoria.
    2.0.7   :   Modificada la forma de leer el header de los paquetes RAW.
    2.0.8   :   Corregido un bug debido al cambio anterior. No se comprobaba bien si el último paquete de RAW era el pseudo-paquete.
     (DANIEL)
    2.0.9   :   Retocando detalles (DANIEL)
	2.0.10	:	Corregido un caso de error que no se notificaba, cuando el fichero de descartes tenía números duplicados
    2.1     :   Incluidas NDLTnext_ex() y NDLTnext()
	2.2		:	Ampliado el máximo tamaño de paquete soportado
    TODO : que el jump pueda saltar a un timestamp en vez de a un numero de paquete
*/


