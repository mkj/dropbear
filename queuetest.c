#include <stdio.h>
#include "queue.h"

int main(int argc, char ** argvc) {

	struct Queue q;
	printf("output should be a b c d e f\n");

	initqueue(&q);

	enqueue(&q, "x");
	dequeue(&q);

	enqueue(&q, "a");
	enqueue(&q, "b");
	enqueue(&q, "y");
	enqueue(&q, "c");
	enqueue(&q, "d");
	enqueue(&q, "e");
	enqueue(&q, "f");

	printf("%s ", dequeue(&q));
	printf("%s ", dequeue(&q));
	dequeue(&q);
	printf("%s ", dequeue(&q));
	printf("%s ", dequeue(&q));
	printf("%s ", dequeue(&q));
	printf("%s ", dequeue(&q));
	printf("\n");
	return 0;
}
