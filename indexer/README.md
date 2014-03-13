indexer
=======

Creates an index using the provided column as key, in which each entry
specifies the byte position in the file. Say we name the chosen column you
choose as <key>, by default an entry is created after passing <interval>
different <keys>. So between an entry and another there are <interval>
different <keys>. <br /><br />
For example: If we want to index a file in which the column
are IPs, by default is indexed in a way that between an IP index entry and the
next there are <interval> different IPs in the original file. Using the option
-L we can change this behaviour. <br /><br />
With the option -L the indexer creates an
entry for every 10 lines. With the option -T, we are assuming that the chosen
column is a timestamp (with ms) so the interval is a time in minutes and the
indexer creates an entry for each <interval>*60 seconds.

#### optional arguments:<br />
<ul>
<li>-h, --help
<p>show this help message and exit</p></li>
<li>-c COLUMN, --column COLUMN
<p>Column to be indexed by, column of the <key>.<br />
Numbering starting in 0. <br /> Zeroth column as default.</p>
</li>
<li>-F, --no-first-line   
<p>Use it if you want to exclude de first line.</p>
</li>
<li>-i INPUT, --input INPUT
<p>Input file. Default: stdin.</p></li>
<li>-I INTERVAL, --interval INTERVAL
<p>With no -L and -T option the interval is how many
   different <keys> we want between an entry and the
   next. <br /> With the -L option it would be the line interval
   whereby each entry is created. <br /> In case of using -T
   option it would mean minutes.</p></li>
<li>-L, --line
<p>Use it if the interval is a number of lines.<br />An entry
will be created for each interval of lines. <br />Not
compatible with option -T.</p></li>
<li>-s SEPARATOR, --separator SEPARATOR
<p>Defines the input field separator. Space character as
default.</p></li>
<li>-S, --sorted
<p>Use it if the provided file is sorted. <br />Unsorted input supported just for -T index mode.</p></li>
<li>-o OUTPUT, --output OUTPUT
<p>Index output filename. Default: stdout.</p></li>
<li>--no-progress-bar
<p>Disable progress bar.</p></li>
<li>-T, --time
<p>Use it if the chosen column is a timestamp, thus the interval would mean minutes.</p></li>
<li>-V, --version
<p>Returns the version of the app.</p></li>
<li>--httpdissector
<p>Default parameters for httpDissector input.</p></li>
<li>--flowprocess
<p>Default parameters for flowProcess input.</p></li>
