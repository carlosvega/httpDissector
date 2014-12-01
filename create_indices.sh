make clean; make
while read filename;
	clear
	do echo "$filename";
	echo "Creating index of file: $filename..."
	sh indice.sh $filename > "$filename.index"
	echo "Index created !"
	clear
	echo "Processing file $filename..."
	format=`echo $filename | awk -F '.' '{print $NF}'`
	/usr/bin/time -v -o "$filename.index.time" ./httpDissector --filter_and=port 80 -i $filename -o /dev/null --$format -x "$filename.index" 2> "$filename.index.error"
done < $1