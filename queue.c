#include <stdlib.h>

#include "options.h"
#include "util.h"
#include "queue.h"

void initqueue(struct Queue* queue) {

	queue->head = NULL;
	queue->tail = NULL;
	queue->count = 0;
}

int isempty(struct Queue* queue) {

	return (queue->head == NULL);
}
	
void* dequeue(struct Queue* queue) {

	void* ret;
	struct Link* oldhead;
	assert(!isempty(queue));
	
	ret = queue->head->item;
	oldhead = queue->head;
	
	if (oldhead->link != NULL) {
		queue->head = oldhead->link;
	} else {
		queue->head = NULL;
		queue->tail = NULL;
		TRACE(("empty queue dequeing"));
	}

	m_free(oldhead);
	queue->count--;
	return ret;
}

void *examine(struct Queue* queue) {

	assert(!isempty(queue));
	return queue->head->item;
}

void enqueue(struct Queue* queue, void* item) {

	struct Link* newlink;

	TRACE(("enter enqueue"));
	newlink = (struct Link*)m_malloc(sizeof(struct Link));

	newlink->item = item;
	newlink->link = NULL;

	if (queue->tail != NULL) {
		queue->tail->link = newlink;
	}
	queue->tail = newlink;

	if (queue->head == NULL) {
		queue->head = newlink;
	}
	queue->count++;
	TRACE(("leave enqueue"));
}
