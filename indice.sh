format=`echo $1 | awk -F '.' '{print $NF}'`
>&2 echo "File format: $format"
./indice_traza -f $1 -p $format -k 100 | \
#paquete, fichero, byte, ts
#acumulado
gawk '{print $1,$3,$4,($3-aux),($1-aux2); aux=$3; aux2=$1}' | \
#paquete, byte, ts, byte_acc, paquete_acc
#indice por ts
gawk 'BEGIN{ts=0;aux=0;acc=0;ctr=0;} {ts=(int($3/10))*10; if(ts<=aux){ctr+=$5}else{printf("%d %d %d %d\n", aux, ctr+$5, byte, pkt); ctr=0; aux=ts; byte=$2; pkt=$1}}' | \
#ts, pkts, byte, paquete
#quitar principio
tail -n +2 | \
#media movil 
# se acumulan los datos del numero de paquetes en la variable SUM (sum+=$2)
# con los primeros datos se calcula la media con los datos que tenemos /1 /2 /3 ... hasta que tenemos tantos datos como el tamaño de la ventana, entonces 1/N ... 
# se guardan los datos previos en un array con N celdas para restar de SUM los datos que se dejan atras
# se imprime sum/count count valdra N (size) cuando se pasen los primeros size elementos.
gawk 'BEGIN{size=10} {mod = NR%size; if(NR<=size){ count++ } else { sum-=array[mod] }; sum+=$2; array[mod]=$2; print $4,1,$3,$1,$2,sum/count}'
#pkt, 1, byte, ts, pkts/s, MEDIApkts/s