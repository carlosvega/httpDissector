#HTTP packet reader   
***    
## What is this project about?

This is a job for the **High Performance Computing and Networking** research group at the **Universidad Autonoma de Madrid**
The aim of the application is to show the response times of HTTP requests.
Afterwards these data is plotted to analyze the HTTP traffic and improve its behaviour.

## Does it use any external libraries?
This application uses just glib and libpcap packages.

## How could I get in touch with you?
You can send me an email to this address: carlosvega@gmx.es

## Dependencies

libpcap and glibc libraries.

If you use __Fedora__ you need make sure these packets are installed:
- make
- gcc
- glib2-devel libpcacp-devel
- And it would be fine if you also install kernel-devel and kernel-headers

If you use __Ubuntu__ you need make sure these packets are installed:
- libpcap-dev
- libglib2.0-dev
 
Dependency tree

            hope
             ||
      glibc——||——libpcap
                   
If you want the shell line to install these packets use this one:
sudo yum install kernel-devel kernel-headers make gcc glib2-devel libpcacp-devel

## Installation
I have created an installer. These are the instructions:

1. Check if you fulfill the dependencies requirements at the depenencies chapter above.
2. You just need to download installer.7z (7z have a really high compression ratio, you must try it!)
3. Uncompress it
4. make
5. ./hope and follow the instructions


### Change log
 - Small changes
 - Added trash collector (Every 10 seconds)
 - Added progress bar (Every 0.5 seconds)
 - The request/response pair is freed right after the response comes
 - Discards the response's data (Memory Optimization)
 - Prints timestamps in UTC
 - Various output format. Two-lines, one line and RRD format. Now print Response message and code.
 - Added file of files option

### Problems to solve


### To do

 - Concurrent version

I got to lunch, see you later.
