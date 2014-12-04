make clean; make
while read filename;
	if [ -z "$filename" ];
	then
		break
	fi

	clear
	do 
	>&2 echo "$filename";
	>&2 echo "Creating index of file: $filename..."
	sh indice.sh $filename > "$filename.index"
	>&2 echo "Index created !"
	echo ""
	clear
	>&2 echo "Processing file $filename..."
	format=`echo $filename | awk -F '.' '{print $NF}'`
	/usr/bin/time -v -o "$filename.index.time" ./httpDissector --filter_and="port 80" -i $filename -o /dev/null --$format -x "$filename.index" 2> "$filename.index.error"
	echo ""
done < $1