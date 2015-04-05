#ifndef __RTE_CHANNEL__
#define __RTE_CHANNEL__

#include <stdint.h>
#include <rte_atomic.h>

typedef struct task* task_t;

typedef struct channel* channel_t; 

struct channel {
  uint16_t capacity;
  rte_atomic16_t size;
  rte_atomic16_t readIndex;
  rte_atomic16_t writeIndex;
  rte_atomic16_t closed;
  task_t producer;
  uint8_t producerIndex;
  task_t consumer;
  uint8_t consumerIndex;
  void *array[0];
};

int channel_is_full(channel_t channel);

int channel_is_empty(channel_t channel);

int channel_is_closed(channel_t channel);

void channel_insert(channel_t channel, void *item);

void *channel_remove(channel_t channel);

void *channel_peek(channel_t channel);

void channel_close(channel_t channel);

void channel_register_producer(channel_t channel, uint8_t index, task_t producer);

void channel_register_consumer(channel_t channel, uint8_t index, task_t consumer);

void channel_notify_consumer(channel_t channel);

int channel_pool_create(uint16_t size, uint16_t ch_size);

void channel_pool_destroy();

channel_t channel_get();

void channel_put(channel_t channel);

#endif // __RTE_CHANNEL__
