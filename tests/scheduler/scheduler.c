#include "scheduler.h"
#include "task.h"

#include <rte_common.h>
#include <rte_eal.h>

void hello(void *data) {
  char *name = data;
  printf("%s: says hello.\n", name);
}

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
  printf("Scheduler test is initializing DPDK system...\n");
  if (rte_eal_init(argc, argv) < 0) {
    // int n = (uint8_t)rte_eth_dev_count();
    rte_exit(-1, "Scheduler test failed to initialize DPDK.");
  }
  printf("Scheduler test is creating a pool of 1024 tasks.");
  task_pool_create(1024);
  printf("Scheduler test is creating a scheduler with 4 execution thread.\n");
  scheduler_init(2);
  for (i = 0; i < 2048; i++) {
    sprintf(name, "task-%d", i);
    printf("Scheduler test is creating task: %s\n", name);
    task_t t = task_create(hello, strdup(name), 0, 0);
    printf("Scheduler is submitting task: %s\n", name);
    if (task_is_runnable(t))
      scheduler_submit(t);
    while(task_is_running(t)); //spin
    task_destroy(t);
  }
  scheduler_destroy();
}
