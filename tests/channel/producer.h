#ifndef __PRODUCER__
#define __PRODUCER__

#include "packet.h"
#include "task.h"
#include "channel.h"

struct producer_data {
  uint32_t bufferCount;
  uint32_t count;
};

void producer_run(task_t This) {
  uint16_t length;
  packet_t pkt;
  struct producer_data *pData = This->data;
  channel_t txChannel = task_get_tx_channel(This, 0);
  //printf("producer_run() of %d started\n", This->id);
  while (pData->bufferCount <= pData->count) {
    if (pData->bufferCount == pData->count) {
      channel_close(txChannel);
      printf("%s %u finished sending %u packets.\n", 
						 This->name, This->id, pData->bufferCount);
      //task_reset_running(This);
      return;
    }
    if (channel_is_full(txChannel)) {
      printf("%s %u TX full %d, sleeping: %u\n", 
						 This->name, This->id, channel_size(txChannel), pData->bufferCount);
      task_reset_running(This);
      return;
    }
    pkt = packet_create_dummy();
    if (pkt) {
      pkt->seq = pData->bufferCount++;
      //printf("Producer %u is sending %u-th buffer\n", This->id, pkt->seq);
      channel_insert(txChannel, pkt);
    }
    else {
      printf("Producer %u failed to create new packet, sleeping: %u\n", 
	     This->id,  pData->bufferCount);
      task_reset_running(This);
      return;
    }
  }
}
#endif /*__PRODUCER__*/
