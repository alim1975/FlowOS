#include <stdio.h>
#include <assert.h>

#include <rte_malloc.h>

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
  assert(stages < MAX_PIPELINE);
  pipeline_t pipe = rte_malloc("pipeline", sizeof(struct pipeline), 0);
  if (pipe == NULL) {
    printf("pipeline_create(): Unable to allocate "
					"memory for pipeline\n");
    return NULL;
  }
  pipe->stages = stages;
  for (i = 0; i < stages; i++)
    TAILQ_INIT(&pipe->tasks[i]);
  
  return pipe;
}

/* Remove a processing pipeline from a flow. */
void pipeline_delete(pipeline_t pipe) {
  int stage;
  task_t task, temp;
  assert(pipe != NULL);
  for (stage = 0; stage < pipe->stages; stage++) {
    /* delete tasks */
    for (task = TAILQ_FIRST(&pipe->tasks[stage]); task != NULL; task = temp) { 
      temp = TAILQ_NEXT(task, list);
      /* decrement ref count */
      TAILQ_REMOVE(&pipe->tasks[stage], task, list);
      //task_put(task);
      //if (task_refcount(task) == 0) {
			//	flowos_remove_task(task->name);
      //}
      task_destroy(task);
    }    
  } 
}

/* Insert a processing task into 
   a processing pipeline at a given position. */
void pipeline_add_task(pipeline_t pipe, task_t task, uint8_t pos) {
  if (pipe == NULL || pipe->stages == 0) {
    printf("pipeline_add_task(): pipeline is empty...\n");
    return;
  }
  if (! task) {
    printf("pipeline_add_task(): task is NULL\n");
    return;
  }

  if (pipe->stages <= pos) {
    printf("pipeline_add_task(): invalid position %d setting 0\n", pipe->stages);
    pos = 0;
  }
  /* add this PM to the list of PMs at this level */
  TAILQ_INSERT_TAIL(&pipe->tasks[pos], task, list);
}

task_t pipeline_find_task(pipeline_t pipe, const char *name) {
  int i;
  task_t task;
  for (i = 0; i < pipe->stages; i++) {
    TAILQ_FOREACH (task, &pipe->tasks[i], list) {
      if (strcmp(task->name, name) == 0)
				return task;
    }
  }
  return NULL;
}
