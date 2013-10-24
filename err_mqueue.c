#include "err_mqueue.h"
 
pthread_t log_thread;

int msqid;
int msgflg = IPC_CREAT | 0666;
key_t key = 1234;
struct msgbuf sbuf;

int running = 0;


void die(char *s)
{
  perror(s);
  exit(1);
}

void *logger(){
	struct msgbuf rcvbuffer;

	if ((msqid = msgget(key, 0666)) < 0){
		die("msgget()");
	}
 	
 	while(running){
		if (msgrcv(msqid, &rcvbuffer, ERR_MSG_QUEUE, 1, 0) >= 0){
			fprintf(stderr, "%s", rcvbuffer.mtext);
    	}
    }

    return NULL;
}

int add_message(){

	if(running == 0){
		return -1;
	}

	size_t buflen = strlen(sbuf.mtext) + 1;

	if(msgsnd(msqid, &sbuf, buflen, IPC_NOWAIT) < 0){
		return -2;
	}

	return 0;
}

int err_mqueue_close(){
	running = 0;
	return 0;
}

int err_mqueue_init(){

	// key = getpid();
	running = 1;
	//Message Type
    sbuf.mtype = 1;

	if ((msqid = msgget(key, msgflg)) < 0){   //Get the message queue ID for the given key
    	return -1;
    }
 
	pthread_create(&log_thread, NULL, logger, NULL);

   
    return 0;

}