#ifndef _QUEUE_H_
#define _QUEUE_H_

struct Link {

	void* item;
	struct Link* link;

};

struct Queue {

	struct Link* head;
	struct Link* tail;
	unsigned int count; /* safety value */

};

void initqueue(struct Queue* queue);
int isempty(struct Queue* queue);
void* dequeue(struct Queue* queue);
void *examine(struct Queue* queue);
void enqueue(struct Queue* queue, void* item);

#endif
