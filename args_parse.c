#include "args_parse.h"

void how_to_use(char *name){
  
	fprintf(stderr, "\n\t\t\t\tHTTP Packet Dissector\n\n");
  fprintf(stderr, "%s [options] -i=input_file\n\n", name);
  fprintf(stderr, "\t-c  --capture=<interface>\tCapture from the given interface\n");
  fprintf(stderr, "\t-f  --filter=<filter>\t\tJoins the default filter with the introduced one.\n");
  fprintf(stderr, "\t-D  --debug=<debug_level>\t\tActivates debug lines.\n");
  fprintf(stderr, "\t-h  --help\t\t\tShows this message.\n");
  fprintf(stderr, "\t-i  --input=<file>\t\tInput file. This parameter is mandatory.\n");
  fprintf(stderr, "\t-I  --input-files\t\tIndicates that the input file is a list of files, the flag -i is still necesary.\n");
  fprintf(stderr, "\t    --log\t\t\tWrites debug stuff in the log (httpDissector)\n");
  fprintf(stderr, "\t-o  --output=<file>\t\tOutput file instead of stdout.\n");
  fprintf(stderr, "\t-p  --pcap\t\t\tSets the input file format as pcap. (Set by Default)\n");
  fprintf(stderr, "\t-P  --parallel=<n_processes>\tParallel processing. Needs number of processes.\n");
  fprintf(stderr, "\t-r  --raw\t\t\tSets the input file format as raw.\n");
  fprintf(stderr, "\t-R  --rrd\t\t\tOnly Prints second and the diff average from that second\n");
  fprintf(stderr, "\t-u  --url=<url>\t\t\tFilter the request by url\n");
  fprintf(stderr, "\t    --sorted\t\t\tSorted output by request timestamp\n");
  fprintf(stderr, "\t-v  --verbose\t\t\tVerbose mode. Shows information about the Garbage Collector\n");
  fprintf(stderr, "\t    --version\t\t\tShows the program version\n\n");


  fprintf(stderr, "\t\t\t\tOUTPUT FORMAT DETAILS\n");
  fprintf(stderr, "Default output\n");
  fprintf(stderr, "\tSourceIP|SourcePort|DestIP|DestPort|ReqTS|ResTS|Diff|ResponseMSG|ResponseCode|URL\n");
  fprintf(stderr, "\t*SourceIP is the requester IP\n");
  fprintf(stderr, "\t*The vertical bar ( | ) has been chosen as the separator character instead of the blank space due to the blank spaces inside the HTTP response message.\n\t It's faster than replace the blank spaces of the messages by low dashes in each message.\n\t It would take a lot of CPU time.\n\n");

  fprintf(stderr, "RRD output\n");
  fprintf(stderr, "\tSEC AVG_DIFF\n");

  fprintf(stderr, "\t\t\t\tFILE OF FILES FORMAT\n");
  fprintf(stderr, "One file path per line.\n");
  fprintf(stderr, "Instead of \"~/file.pcap\" use the absolute path \"/Users/user/file.pcap\"\n");
  fprintf(stderr, "There is no problem using \"../file.pcap\" paths.\n\n");

  fprintf(stderr, "\t\t\t\tPARALLEL PROCESSING\n");
  fprintf(stderr, "When no output file has been specified, the information is printed in the Standard Output\n");
  fprintf(stderr, "Otherwise a new output file will be created for each processed file.\n");
  fprintf(stderr, "The naming pattern it's the specified filename followed by a number.\n");
  fprintf(stderr, "This number represents the file position in the provided file list.\n");

  fprintf(stderr, "\n");

  return;
}

struct args_parse parse_args(int argc, char **argv){

  struct args_parse options;
  options.input       = NULL;
  options.output      = NULL;
  options.filter      = NULL;
  options.url         = NULL;
  options.parallel    = 0;
  options.raw         = -1;
  options.rrd         = 0;
  options.debug       = 0;
  options.log         = 0;
  options.files       = 0;
  options.err         = -1;
  options.interface   = NULL;
  options.collector   = 1;
  options.verbose     = 0;
  options.version     = 0;
  options.sorted      = 0;

  strcpy(options.errbuf, "Invalid arguments");

	int next_op;

	/* Una cadena que lista las opciones cortas válidas */
	const char* const short_op = "D:hrIvpf:i:P:o:u:c:" ;

	/* Una estructura de varios arrays describiendo los valores largos */
	const struct option long_op[] =
	{
		{ "help",           0,  NULL,   'h'},
    { "debug",          1,  NULL,   'D'},
		{ "output",         1,  NULL,   'o'},
		{ "raw",		        0, 	NULL, 	'r'},
    { "no-collector",   0,  NULL,   'C'},
    { "sorted",         0,  NULL,   'S'},
    { "log",            0,  NULL,   'L'},
		{ "pcap",			      0, 	NULL, 	'p'},
		{ "input",		      1, 	NULL, 	'i'},
    { "parallel",       1,  NULL,   'P'},
    { "capture",        1,  NULL,   'c'},
		{ "filter", 		    1, 	NULL, 	'f'},
    { "url",            1,  NULL,   'u'},
    { "verbose",        0,  NULL,   'v'},
    { "input-files",    0,  NULL,   'I'},
    { "version",        0,  NULL,   'V'},
    { "rrd",            0,  NULL,   'R'},
		{ NULL,             0,  NULL,    0 }
	};

	while(1){
		/* Llamamos a la función getopt */
	  next_op = getopt_long (argc, argv, short_op, long_op, NULL);

	 if (next_op == -1)
      	break; /* No hay más opciones. Rompemos el bucle */

        switch (next_op)
      	{
        case 'h' : /* -h o --help */
          options.err = -3;
          strcpy(options.errbuf, "Help:");
          return options;
			  case 'D' : 
          options.debug = atoi(optarg);
          break;
        case 'i' : /* -i o --input */
          options.input = optarg;
          options.err = 0;
          break;

        case 'P' : /* -P o --parallel */
          options.parallel = atoi(optarg);
          options.err = 0;
          break;

        case 'R' : /* -rrd */
          options.rrd = 1;
          options.sorted = 1;
          break;

        case 'S' : /* --sorted */
          options.sorted = 1;
          break;

        case 'c' : /*-c o --capture */
          if(options.input){
            options.err = -2;
            strcpy(options.errbuf, "Input from file & interface? Just choose one");
            return options;
          }
          options.interface = optarg;
          options.err = 0;
          break;

        case 'o' : /* -o ó --output */
          options.output = optarg; /* optarg contiene el argumento de -o */
          break;

        case 'r' : /*raw*/
          if(options.raw == 0){
            options.err = -2;
            strcpy(options.errbuf, "Raw & pcap? Just choose one");
            return options;
          }
          options.raw = 1;
          break;

        case 'p' : /*pcap*/
          if(options.raw == 1){
            options.err = -2;
            strcpy(options.errbuf, "Raw & pcap? Just choose one");
          	return options;
          }
          options.raw = 0;
          break;

        case 'f' : /*filter*/
        	options.filter = optarg;
        	break;

        case 'v' :
          options.verbose = 1;
          break;

        case 'I' :
          options.files = 1;
          break;

        case 'u' :
          options.url = optarg;
          break;

        case 'C' :
          options.collector = 0;
          break;

        case 'L' :
          options.log = 1;
          break;

        case 'V' :
          options.err = 0;
          options.version = 1;
          break;

        case '?' : /* opción no valida */
          options.err = -1;
          strcpy(options.errbuf, "Invalid arguments");
          return options;

        case -1 : /* No hay más opciones */
          break;

        default : /* Algo más? No esperado. Abortamos */
          options.err = -1;
          strcpy(options.errbuf, "Invalid arguments");
          return options;
	  }
	}


  if(options.raw == -1){
    options.raw = 0;
  }

  return options;

}