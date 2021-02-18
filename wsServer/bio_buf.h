/*
 * bio.h
 *
 *  Created on: 2014年10月22日
 *      Author: lily
 */

#ifndef _BIO_BUF_H
#define _BIO_BUF_H


typedef struct bio_buf_st{
	char *heap;
	char *head, *tail;
	int capacity;
	int size;
}*bioBuf_t;


bioBuf_t    bio_buf_new(int);
void         bio_buf_free(bioBuf_t b);
int          bio_buf_extend(bioBuf_t b, int grow);
int         bio_buf_append(bioBuf_t b, const void* src, int len);
int         bio_buf_consume(bioBuf_t b, int use);
int         bio_buf_init(bioBuf_t);

#endif /* BIO_H_ */
