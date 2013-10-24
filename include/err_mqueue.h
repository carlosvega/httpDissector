#ifndef _err_mqueue
#define _err_mqueue

#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ERR_MSG_QUEUE 2048

// #define ERR_MSG(...) do{snprintf(sbuf.mtext, ERR_MSG_QUEUE, __VA_ARGS__); add_message();}while(0)
// #define ERR_MSG(...) do{fprintf(stderr, __VA_ARGS__);}while(0)

struct msgbuf
{
    long    mtype;
    char    mtext[ERR_MSG_QUEUE];
};

int add_message();

int err_mqueue_close();

int err_mqueue_init();

#endif