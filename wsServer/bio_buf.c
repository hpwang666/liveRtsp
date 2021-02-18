#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "bio_buf.h"



bioBuf_t bio_buf_new(int size)
{
	bioBuf_t b =(bioBuf_t)calloc(1, sizeof(struct bio_buf_st));
	b->capacity = size;
	b->tail = b->head = b->heap = calloc(1,size);
	return b;
}

int bio_buf_init(bioBuf_t b)
{
	b->tail = b->head = b->heap;
	b->size =0;
	memset(b->heap,0,b->capacity);
	return 0;
}

void bio_buf_free(bioBuf_t b){
	if(b->heap)
		free(b->heap);
	free(b);
}


int bio_buf_extend(bioBuf_t b, int grow){
	int tailTOend =b->capacity- (b->tail - b->heap)-1; 
	int newsize;
	if(tailTOend < grow){
		memmove(b->heap, b->head, b->size);
		b->head = b->heap;
		b->tail = b->head + b->size;
		memset(b->tail,0,(b->capacity - b->size));
	}
	newsize =  b->size + grow;
	if(newsize > b->capacity){
		char* tmp;
		printf(">>>realloc %d %d\r\n",grow,b->size);//正常情况下可以实现缓存循环利用
#if 0		
		tmp = realloc(b->heap, newsize);
		b->heap = tmp;
		b->head = b->heap;
		b->tail = b->head + b->size;
		b->capacity = newsize;
		memset(b->tail,0,(b->capacity - b->size));
#endif
		memset(b->heap,0,b->capacity);
		b->tail= b->heap;
		b->head = b->heap;
		b->size = 0;
		

	return 1;
	}
	
	return 0;
}
int bio_buf_append(bioBuf_t b, const void* src, int len)
{
	int ret = bio_buf_extend(b, len);
	memcpy(b->tail, src, len);
	b->tail += len;
	b->size += len;
	return ret;
}

int bio_buf_consume(bioBuf_t b, int use)
{
	b->size -= use;
	if(b->size <= 0){
		b->head = b->tail = b->heap;
		b->size = 0;
	} else {
		b->head += use;
	}
	return 0;
}
