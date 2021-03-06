#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "alist.h"
#include "args_parse.h"

extern struct args_parse options;

#define FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

/*
	THE LAST HEADER MUST TO END WITH \r\n
*/
int getLines(char *str, http_header *http_hdr)
{

	if (http_hdr == NULL || str == NULL) {
		return -1;
	}

	int n_lines = 0;
	char *ptr, *end_hdr, *value;
	ptr = end_hdr = value = NULL;
	//http_hdr->original = str;

	list_node *node_ptr = (list_node *) malloc(sizeof(list_node));
	list_node *last = NULL;

	if (!node_ptr) {
		return -1;
	}

	node_ptr->next = NULL;
	node_ptr->key = NULL;
	node_ptr->value = NULL;
	http_hdr->fields = node_ptr;

	ptr = str;

	while (*ptr != '\0' && ptr) {

		value = strchr(ptr, ':');

		if (value == NULL) {
			if (n_lines != 0) {
				FREE(last->next);
				break;

			} else {
				return -1;
			}
		}

		node_ptr->key = (char *) calloc(((value - ptr) + 1), sizeof(char));

		if (node_ptr->key == NULL) {
			return -1;
		}

		memcpy(node_ptr->key, ptr, (value - ptr));

		ptr = value + 2; //Jumps ':' and ' '
		end_hdr = strchr(ptr, '\r');

		if (end_hdr == NULL) { //POSIBLE FIN CORRECTO SI EL HEADERS ESTA CORTADO
			http_hdr->n_fields = n_lines;
			node_ptr->value = (char *) calloc((strlen(ptr) + 1), sizeof(char));

			if (node_ptr->value == NULL) {
				return 1;
			}

			memcpy(node_ptr->value, ptr, strlen(ptr));
			return 1;
		}

		node_ptr->value = (char *) calloc(((end_hdr - ptr) + 1), sizeof(char));

		memcpy(node_ptr->value, ptr, (end_hdr - ptr));

		end_hdr += 2; //Jumps \r\n
		ptr = end_hdr;
		n_lines++;

		if (*(ptr) == '\0') {
			break;
		}

		node_ptr->next = (list_node *) malloc(sizeof(list_node));
		last = node_ptr;
		node_ptr = node_ptr->next;
		node_ptr->next = NULL;
		node_ptr->key = NULL;
		node_ptr->value = NULL;
	}

	http_hdr->n_fields = n_lines;

	return 0;
}

char *find(char *key, list_node *list)
{

	if (list == NULL) {
		return NULL;
	}

	int found = 1;
	list_node *ptr = list;

	while ((found = strcmp(key, ptr->key)) && ptr->next) {
		ptr = ptr->next;
	}

	return (found ? NULL : ptr->value);
}

void http_free_header(http_header *http_hdr)
{

	if (http_hdr == 0) {
		return;
	}

	if (options.debug > 1) {
		fprintf(stderr, "3.1, ");
	}

	FREE(http_hdr->original);

	if (options.debug > 1) {
		fprintf(stderr, "3.2, ");
	}

	free_list(http_hdr->fields);

	if (options.debug > 1) {
		fprintf(stderr, "3.3");
	}

	return;
}

void free_list(list_node *list)
{

	if (list == 0) {
		return;
	}

	if (options.debug > 2) {
		fprintf(stderr, "3.2.1, ");
	}

	FREE(list->key);

	if (options.debug > 2) {
		fprintf(stderr, "3.2.2, ");
	}

	FREE(list->value);

	if (options.debug > 2) {
		fprintf(stderr, "3.2.3, ");
	}

	//fprintf(stderr, "%s: %s\n", list->key, list->value);

	free_list(list->next);

	if (options.debug > 2) {
		fprintf(stderr, "3.2.4, ");
	}

	FREE(list);

	if (options.debug > 2) {
		fprintf(stderr, "3.2.5, ");
	}

}