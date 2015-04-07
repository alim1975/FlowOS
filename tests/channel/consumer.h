#ifndef __CONSUMER__
#define __CONSUMER__

struct consumer_data {
  uint32_t count;
};

#include <assert.h>

#include "packet.h"
#include "task.h"
#include "channel.h"

void consumer_run(task_t This) {
  uint16_t length;
  packet_t pkt;
  struct consumer_data *cData = This->data;
  channel_t rxChannel = task_get_rx_channel(This, 0);
  while (true) {
    if (channel_is_closed(rxChannel) && channel_is_empty(rxChannel)) {
      printf("%s %u finished, received %u packets.\n", 
						 This->name, This->id, cData->count);
      return;
    }
    if (channel_is_empty(rxChannel)) {
      printf("%s %u RX empty, sleeping: %u\n", This->name, This->id, cData->count); 
      channel_notify_producer(rxChannel);
      usleep(10);
      continue;
    }
    else {
      pkt = channel_remove(rxChannel);
      assert(pkt);
      //printf("Consumer received %u-th buffer\n", pkt->seq);
      cData->count++;
      packet_delete(pkt);
    }
  }
}
#endif /* __CONSUMER__ */
