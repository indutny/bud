/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stddef.h>
#include <sys/types.h>  /* ssize_t */

/* Tweak these for potential memory/throughput tradeoffs */

/* 16 * 1024 - 3 * 8 - 360, to make `proxystate` aligned */
#define RING_BUFFER_LEN 16000
#define RING_MAX_SIZE 64000

typedef struct bufent {
    ssize_t read_pos;
    ssize_t write_pos;
    struct bufent* next;
    char data[RING_BUFFER_LEN];
} bufent;

typedef struct ringbuffer {
    ssize_t length;
    bufent* read_head;
    bufent* write_head;
    bufent head;
} ringbuffer;

void ringbuffer_init(ringbuffer* rb);
void ringbuffer_destroy(ringbuffer* rb);

ssize_t ringbuffer_read_into(ringbuffer* rb, char* out, ssize_t length);
char* ringbuffer_read_next(ringbuffer* rb, ssize_t* length);
void ringbuffer_read_skip(ringbuffer* rb, ssize_t length);
void ringbuffer_read_pop(ringbuffer *rb);

ssize_t ringbuffer_write_into(ringbuffer* rb, const char* data, ssize_t length);
char* ringbuffer_write_ptr(ringbuffer* rb, ssize_t* length);
int ringbuffer_write_append(ringbuffer* rb, ssize_t length);

ssize_t ringbuffer_size(ringbuffer* rb);
int ringbuffer_is_empty(ringbuffer* rb);
int ringbuffer_is_full(ringbuffer* rb);

#endif /* RINGBUFFER_H */
