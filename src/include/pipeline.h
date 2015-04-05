#ifndef __PIPELINE_H__
#define __PIPELINE_H__

#include "task.h"

#define MAX_PIPE 8

typedef char* string_t;

struct pipeline {
  int stages;
  TAILQ_HEAD(, task) tasks[MAX_PIPE];
};
typedef struct pipeline* pipeline_t;
 
pipeline_t pipeline_create(int);

void pipeline_add_task(pipeline_t, task_t, uint8_t);

task_t pipeline_find_task(pipeline_t, string_t name);

void pipeline_remove_task(pipeline_t, task_t, int);

void pipeline_delete(pipeline_t);

#define pipeline_get_stages(p) ((p)->stages)

#define pipeline_get_pms(p, s) (&(p)->pms[s]) 

#endif /* __PIPELINE_H__ */
