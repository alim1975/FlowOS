#include <rte_common.h>
#include <rte_eal.h>

#include "scheduler.h"
#include "task.h"
#include "producer.h"
#include "consumer.h"

#define MAIN main
#ifdef RTE_EXEC_ENV_BAREMETAL
#define MAIN _main
#endif

int MAIN(int argc, char **argv) {
  int i;
  char name[32];
  argc = 3;
  argv[1] = "-cf";
  argv[2] = "-n1";
  printf("Channel test is initializing DPDK system...\n");
  if (rte_eal_init(argc, argv) < 0) {
    rte_exit(-1, "Channel test failed to initialize DPDK.");
  }
  printf("Channel test is creating a pool of 4 tasks.");
  task_pool_create(2);
  channel_pool_create(4);
  packet_cache_init();
  printf("Channel test is creating a scheduler with 4 execution thread.\n");
  scheduler_init(2);
  printf("Creating producer task...\n");
  struct producer_data pData;
  struct consumer_data cData;
  pData.bufferCount = 0;
  pData.count = 10000;
  cData.count = 0;

  task_t pt = task_create(producer_run, "Producer", &pData, 0, 1);
  printf("Creating consumer task...\n");
  task_t ct = task_create(consumer_run, "Consumer", &cData, 1, 0);
  assert(task_connect(pt, ct) == 0);
  printf("Connecting producer -> consumer...\n");
  channel_t ch = pt->txChannels[0];
  printf("Producer %d consumer %d channel producer %d channel consumer %d producer index %d consumer index %d\n",
	 pt->id, ct->id, ch->producer->id, ch->consumer->id, ch->producerIndex, ch->consumerIndex);

  printf("Starting producer task, hit any key to exit\n");
  scheduler_submit(pt);
  getchar();
  printf("Producer count %u consumer %u\n", pData.bufferCount, cData.count);
  task_destroy(pt);
  task_destroy(ct);
  
  scheduler_destroy();
}
