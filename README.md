#HTTP packet reader   
***  
## What is this project about?

This is a job for the **High Performance Computing and Networking** research group at the **Universidad Autonoma de Madrid**
The aim of the application is to show the response times of HTTP requests.
Afterwards these data is plotted to analyze the HTTP traffic and improve its behaviour.

## Does it use any external libraries?
This application uses libpcap package.

## How could I get in touch with you?
You can send me an email to this address: carlos.vega@uam.es

## Dependencies

libpcap library.

If you use __Fedora__ you need make sure these packets are installed:
- make
- gcc or clang
- libpcacp-devel
- And it would be fine if you also install kernel-devel and kernel-headers

If you use __Ubuntu__ you need make sure these packets are installed:
- libpcap-dev

Dependency tree

        httpDissector
             ||
             ||——libpcap
                   
If you want the shell line to install these packets use this one:
sudo yum install kernel-devel kernel-headers make gcc libpcacp-devel

## Installation

1. Check if you fulfill the dependencies requirements at the dependencies chapter above.
2. You just need to download the project
3. Uncompress it
4. make
5. ./httpDissector and follow the instructions

### Change log

__Version 2.x __

 - Added support for HPCAP. Compile with make HPCAP
 - Added support for "100 Continue" HTTP transacctions
 - Improved the makefile with a LOW_MEMORY option. make LOW_MEMORY
 - Improved the makefile. If clang doesn't exists, use gcc instead automatically 
 - Added --agent option to print the User Agent header
 - Added vlan support

__Version 2.1 __

 - Glib is no longer required.
 - The hash table is a double linked list of node_l (list.c)
 - To improve the performance the allocs and frees of memory during the process have been avoided. There's no allocs during the callbacks.
 - There are three pools of variables. The `node_l` pool, for general purpose. The `hash_value` pool for the connexions and the `request` pool for the requests.
 - Modified packet_info structure. Created request and response structures, simpler and cleaner.
 - Avoid parsing the HTTP headers.
 - Added a sorted list of active connexions. Sorted by last used.
 - Thanks of this last change the garbage collector is quicker. We process the list starting by the last and when one of the connexions doesn't need to be deleted the rest neither.
 - Changed Glib threads for pthread ones.
 - Changed Glib mutex for `pthread_mutex_t`.
 - Added a little control to avoid wrong matches when a retransmissions happens. This will be improved.

Version 1

 - Small changes
 - Added trash collector (Every 10 seconds)
 - Added progress bar (Every 0.5 seconds)
 - The request/response pair is freed right after the response comes
 - Discards the response's data (Memory Optimization)
 - Prints timestamps in UTC
 - Added some output formats. Two-lines, one line and RRD format. Now print Response message and code.
 - Added file of files option
 - Added log option for memory and read speed information.
 - At the end of each file the speed in packets/sec is printed
 - Added packets/sec info to the log
 - The father acted as a seeder of children. One child per file but one after another. The child dies after processing the file and the father sows another child for the next file. Now this system have changed. No more children. Just a lonely father that processes all the files by himself one after another.
 - In the previous version the hash table was destroyed after processing a file. So if a file has a request which is satisfied in another file, the dissector will never know and will discard that strange response. But now the table is not destroyed so the above problem disappears.
 - Now the progress bar represents the progress for the list of files instead of file per file as before.
 - The final output message has been simplified.
 - Fixed double free when invalid file format.
 

### Problems to solve

 - Multicore version => Solved thanks to Paula's feeder !
 - Take account of retransmissions and lost packets to ensure that there are no wrong matches. => Solved thanks to the option --noRtx 

I got to lunch, see you later.
