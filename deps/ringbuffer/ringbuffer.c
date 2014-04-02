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

#include "ringbuffer.h"
#include <assert.h>  /* assert */
#include <stdlib.h>  /* malloc/free */
#include <string.h>  /* memcpy */
#include <stdio.h>  /* memcpy */

#define RB_BUF_SIZE(b) ((b)->write_pos - (b)->read_pos)

void ringbuffer_bufent_init(bufent* b) {
  b->read_pos = 0;
  b->write_pos = 0;
  b->next = NULL;
}

void ringbuffer_init(ringbuffer* rb) {
  rb->length = 0;
  ringbuffer_bufent_init(&rb->head);
  rb->head.next = &rb->head;
  rb->read_head = &rb->head;
  rb->write_head = &rb->head;
}


void ringbuffer_destroy(ringbuffer* rb) {
  bufent* current;
  bufent* next;

  current = rb->head.next;
  while (current != &rb->head) {
    next = current->next;
    free(current);
    current = next;
  }

  rb->read_head = NULL;
  rb->write_head = NULL;
}


/* Free excessive data */
void ringbuffer_free_empty(ringbuffer* rb) {
  bufent* child;
  bufent* cur;
  bufent* prev;
  bufent* next;

  child = rb->write_head->next;
  if (child == rb->write_head || child == rb->read_head)
    return;
  cur = child->next;
  if (cur == rb->write_head || cur == rb->read_head)
    return;

  prev = child;
  while (cur != rb->read_head) {
    /* Skip embedded buffer, and continue deallocating
     * again starting from it
     */
    if (cur == &rb->head) {
      prev->next = cur;
      prev = cur;
      cur = rb->head.next;
      continue;
    }
    assert(cur != rb->write_head);
    assert(cur->write_pos == cur->read_pos);

    next = cur->next;
    free(cur);
    cur = next;
  }
  assert(prev == child || prev == &rb->head);
  prev->next = cur;
}


void ringbuffer_try_move_read_head(ringbuffer* rb) {
  while (rb->read_head->read_pos != 0 &&
         rb->read_head->read_pos == rb->read_head->write_pos) {
    rb->read_head->read_pos = 0;
    rb->read_head->write_pos = 0;

    /* But not get beyond rb->write_head */
    if (rb->read_head != rb->write_head)
      rb->read_head = rb->read_head->next;
  }
}


size_t ringbuffer_read_into(ringbuffer* rb, char* out, size_t length) {
  size_t bytes_read;
  size_t expected;
  size_t offset;
  size_t left;
  bufent* read_head;
  size_t avail;

  bytes_read = 0;
  expected = ringbuffer_size(rb) > length ? length : ringbuffer_size(rb);
  offset = 0;
  left = length;

  while (bytes_read < expected) {
    read_head = rb->read_head;
    assert(read_head->read_pos <= read_head->write_pos);
    avail = RB_BUF_SIZE(read_head);
    if (avail > left)
      avail = left;

    /* Copy data */
    if (out != NULL)
      memcpy(out + offset, read_head->data + read_head->read_pos, avail);
    read_head->read_pos += avail;

    /* Move pointers */
    bytes_read += avail;
    offset += avail;
    left -= avail;

    /* Move to next buffer */
    ringbuffer_try_move_read_head(rb);
  }
  assert(expected == bytes_read);
  rb->length -= bytes_read;

  /* Free all empty buffers, but write_head's child */
  ringbuffer_free_empty(rb);

  return bytes_read;
}


char* ringbuffer_read_next(ringbuffer* rb, size_t* length) {
  *length = RB_BUF_SIZE(rb->read_head);
  return rb->read_head->data + rb->read_head->read_pos;
}


size_t ringbuffer_read_nextv(ringbuffer* rb,
                             char** out,
                             size_t* size,
                             size_t* count) {
  size_t i;
  size_t max;
  size_t total;
  bufent* pos;

  pos = rb->read_head;
  max = *count;
  total = 0;
  for (i = 0; i < max; i++) {
    size[i] = RB_BUF_SIZE(pos);
    total += size[i];
    out[i] = pos->data + pos->read_pos;

    /* Don't get past write head */
    if (pos == rb->write_head)
      break;
    else
      pos = pos->next;
  }

  if (i == max)
    *count = i;
  else
    *count = i + 1;

  return total;
}


void ringbuffer_read_skip(ringbuffer* rb, size_t length) {
  ringbuffer_read_into(rb, NULL, length);
}


void ringbuffer_read_pop(ringbuffer* rb) {
  size_t avail;

  avail = RB_BUF_SIZE(rb->read_head);
  ringbuffer_read_skip(rb, avail);
}


int ringbuffer_try_allocate_for_write(ringbuffer* rb) {
  bufent* next;

  /* If write head is full, next buffer is
   * either read head or not empty.
   */
  if (rb->write_head->write_pos == RING_BUFFER_LEN &&
      (rb->write_head->next == rb->read_head ||
       rb->write_head->next->write_pos != 0)) {
    next = malloc(sizeof(bufent));
    if (next == NULL)
      return -1;
    ringbuffer_bufent_init(next);
    next->next = rb->write_head->next;
    rb->write_head->next = next;
  }

  return 0;
}


size_t ringbuffer_write_into(ringbuffer* rb,
                             const char* data,
                             size_t length) {
  size_t offset;
  size_t left;
  size_t to_write;
  size_t avail;
  bufent* write_head;

  offset = 0;
  left = length;
  while (left > 0) {
    to_write = left;
    write_head = rb->write_head;
    assert(write_head->write_pos <= RING_BUFFER_LEN);
    avail = RING_BUFFER_LEN - rb->write_head->write_pos;

    if (to_write > avail)
      to_write = avail;

    /* Copy data */
    memcpy(write_head->data + write_head->write_pos,
        data + offset,
        to_write);

    /* Move pointers */
    left -= to_write;
    offset += to_write;
    rb->length += to_write;
    write_head->write_pos += to_write;
    assert(write_head->write_pos <= RING_BUFFER_LEN);

    /* Go to next buffer if there still are some bytes to write */
    if (left != 0) {
      assert(write_head->write_pos == RING_BUFFER_LEN);
      if (ringbuffer_try_allocate_for_write(rb))
        return offset;
      rb->write_head = write_head->next;

      /* Read head may be full */
      ringbuffer_try_move_read_head(rb);
    }
  }
  assert(left == 0);

  return 0;
}


char* ringbuffer_write_ptr(ringbuffer* rb, size_t* length) {
  size_t available;

  available = RING_BUFFER_LEN - rb->write_head->write_pos;
  if (*length == 0 || available < *length)
    *length = available;

  return rb->write_head->data + rb->write_head->write_pos;
}


int ringbuffer_write_append(ringbuffer* rb, size_t length) {
  rb->write_head->write_pos += length;
  rb->length += length;
  assert(rb->write_head->write_pos <= RING_BUFFER_LEN);

  /* Allocate new buffer if write head is full,
   * and there're no other place to go
   */
  if (ringbuffer_try_allocate_for_write(rb))
    return -1;

  if (rb->write_head->write_pos == RING_BUFFER_LEN) {
    rb->write_head = rb->write_head->next;

    /* Read head may be full */
    ringbuffer_try_move_read_head(rb);
  }

  return 0;
}


int ringbuffer_insert(ringbuffer* rb,
                      size_t off,
                      const char* data,
                      size_t length) {
  bufent* b;
  bufent* next;
  bufent* start;
  size_t left;
  size_t offset;
  int r;

  assert(length < RING_BUFFER_LEN);

  /* Find owner of `off` */
  left = ringbuffer_size(rb);
  start = rb->read_head;
  while (off != 0) {
    if (off < RB_BUF_SIZE(start))
      break;
    off -= RB_BUF_SIZE(start);
    left -= RB_BUF_SIZE(start);
    start = start->next;
  }

  /* Shift everything after `off` forward by `length` */
  b = rb->write_head;

  /* Ensure that we have enough space for shift */
  r = ringbuffer_write_append(rb, length);
  if (r != 0)
    return r;

  next = rb->write_head;
  while (left > 0) {
    /* Copy part of the data from the end of current to the next buffer */
    if (next != b)
      memcpy(next->data, b->data + RING_BUFFER_LEN - length, length);

    /* Move rest inside current buffer */
    offset = b->read_pos;
    if (b == start)
      offset += off;

    if (offset + length < RING_BUFFER_LEN) {
      memmove(b->data + offset + length,
              b->data + offset,
              RING_BUFFER_LEN - offset - length);
    }

    if (b == start)
      break;

    left -= RB_BUF_SIZE(b);

    /* Select previous buffer, O(N) */
    next = b;
    b = start;
    while (b->next != next)
      b = b->next;
  }

  /* Copy input data into the free space */
  if (off + length > RING_BUFFER_LEN) {
    size_t delta;

    delta = off + length - RING_BUFFER_LEN;
    memcpy(start->data + off, data, length - delta);
    memcpy(next->data, data + length - delta, delta);
  } else {
    memcpy(start->data + off, data, length);
  }

  return 0;
}


size_t ringbuffer_size(ringbuffer* rb) {
  return rb->length;
}


int ringbuffer_is_empty(ringbuffer* rb) {
  return ringbuffer_size(rb) == 0;
}


int ringbuffer_is_full(ringbuffer* rb) {
  return ringbuffer_size(rb) >= RING_MAX_SIZE;
}
