#include <stdio.h>

#include <rte_malloc.h>

#include "pmodule.h"
#include "pipeline.h"
#include "task.h"

/*
  Create a processing pipeline for a flow with 
  a fixed number of stages. A processing module 
  is attached to the flow at a certain stage.
  One PM at each stage makes the pipeline serial. 
  Multiple PMs are attached to the same stage
  for concurrent processing. Initialize a HEAP 
  for each stage to manage tail pointers in 
  concurrent flow processing. 
*/
struct pipeline *pipeline_create(int stages) {
  int i;
  assert(stages < MAX_PIPE);
  struct pipeline *p = rte_malloc("pipeline", sizeof(struct pipeline), 0);
  if (p == NULL) {
    print("pipeline_create(): Unable to allocate "
	   "memory for pipeline\n");
    return NULL;
  }
  p->stages = stages;
  for (i = 0; i < stages; i++)
    TAILQ_INIT(&p->pms[i]);
  
  return p;
}

/* Remove a processing pipeline from a flow. */
void pipeline_delete(struct pipeline *p) {
  int stage;
  struct flowos_pm *pm, *temp;
  if (p == NULL) return;
  for (stage = 0; stage < p->stages; stage++) {
    /* delete PMs */
    for (pm = TAILQ_FIRST(&p->pms[stage]); pm != NULL; pm = temp) { 
      temp = TAILQ_NEXT(pm, list);
      /* decrement ref count */
      TAILQ_REMOVE(&p->pms[stage], pm, list);
      task_put(pm->task);
      if (task_refcount(pm->task) == 0) {
	flowos_remove_pm(pm->task->name);
      }
      pm_delete(pm);
    }    
  } 
}

/* Insert a processing module (pm) into 
   a processing pipeline (p) at position (pos). */
void pipeline_add_pm(struct pipeline *p, struct flowos_pm *pm, uint8_t pos) {
  if (p == NULL || p->stages == 0) {
    printf("pipeline_add_pm(): pipeline is empty...\n");
    return;
  }
  if (! pm) {
    printf("pipeline_add_pm(): pm is NULL\n");
    return;
  }

  if (p->stages <= pos) {
    printf("pipeline_add_pm(): invalid position %d setting 0\n", p->stages);
    pos = 0;
  }
  /* add this PM to the list of PMs at this level */
  TAILQ_INSERT_TAIL(&p->pms[pos], pm, list);
}

struct flowos_pm *pipeline_find_pm(struct pipeline *p, const char *name) {
  int i;
  struct flowos_pm *pm;
  for (i = 0; i < p->stages; i++) {
    TAILQ_FOREACH (pm, &p->pms[i], list) {
      if (strcmp(pm->task->name, name) == 0)
	return pm;
    }
  }
  return NULL;
}
