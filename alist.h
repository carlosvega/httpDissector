#ifndef _alist
#define _alist

typedef struct _list_node {
    struct _list_node* next;
    char* key;
    char* value;
} list_node;

typedef struct {
    list_node* fields;
    char * original;
    int n_fields;
} http_header;

int getLines(char * str, http_header *http_hdr);
void free_list(list_node * list);
void http_free_header(http_header *http);
char * find(char * key, list_node* list);
int split_header(const char *str, char *a, char *b, char token);

#endif
