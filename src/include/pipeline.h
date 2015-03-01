#ifndef _PIPELINE_H_
#define _PIPELINE_H_

#define MAX_PIPE 8

struct flowos_pm;

struct pipeline {
  int stages;
  TAILQ_HEAD(, flowos_pm) pms[MAX_PIPE];
};
 
struct pipeline *pipeline_create(int);

void pipeline_add_pm(struct pipeline *, struct flowos_pm *, uint8_t);

struct flowos_pm *pipeline_find_pm(struct pipeline *pipe, const char *name);

void pipeline_remove_pm(struct pipeline *, struct flowos_pm *, int);

void pipeline_delete(struct pipeline *);

#define pipeline_get_stages(p) ((p)->stages)

#define pipeline_get_pms(p, s) (&(p)->pms[s]) 

#endif /* _PIPELINE_H_ */
