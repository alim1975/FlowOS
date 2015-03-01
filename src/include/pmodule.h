#ifndef _PMODULES_H_
#define _PMODULES_H_

#include "messageq.h"
#include "flow.h"
#include "cmdline.h"
#include "streamp.h"

/* PM types */
#define PM_RONLY 1
#define PM_RDWR  2

/* status of a packet after a PM has finished processing */
#define PM_CLEAN   0
#define PM_DIRTY   1
#define PM_DONE    2
#define PM_ERROR   3

#define PM_SET_TYPE(type) \
  int STRCAT(FLOWOS_PMNAME, _type)(void)	\
  {						\
    return type;				\
  } 

#define PM_SET_PROTOCOL(proto)			\
  char* STRCAT(FLOWOS_PMNAME, _protocol)(void)	\
  {						\
    return #proto;				\
  } 

#define PM_SET_MSGCOUNT(msgmax) \
  int STRCAT(FLOWOS_PMNAME, _nummsg)(void)	\
  {						\
    return msgmax;				\
  } 						\
  
#define PM_DEF_INIT()				\
  int mymod_init(void);				\
  module_init(mymod_init);			\
  int mymod_init(void)

#define PM_DEF_EXIT()				\
  void mymod_deinit(void);			\
  module_exit(mymod_deinit);			\
  void mymod_deinit(void)

#define PM_DEF_MAIN()				\
  int STRCAT(FLOWOS_PMNAME, _process)(struct flowos_pm *PM)

#define PM_DEF_MSGHANDLER(type)			\
  int STRCAT4(FLOWOS_PMNAME, _, type, _msghandler) \
       (const struct flowos_pm *PM, struct flowos_pmhdr *MSG) 

#define PM_RESPONSE(code, ret, len) \
  pm_send_response(MSG, code, ret, len)

#define PM_SET_TLDATA(data) PM->info = &data

#define PM_GET_TLDATA() PM->info

#define BEGIN_PROCESS(pm, head, tail)		\
  while(1){					\
    pm_process_message(pm);			\
    pm_update_head(pm);				\
    if(pm_is_empty(pm)){			\
      task_done(task_self());			\
      return;					\
    }						\
    head = (pm)->head;				\
    pthread_mutext_lock(&(pm)->tail_lock);     	\
    tail = (pm)->tail;				\
    pthread_mutex_unlock(&(pm)->tail_lock);

#define END_PROCESS()  }

typedef int(*pm_main_fn)(struct flowos_pm *);
typedef int (*flowos_pmmsg_handler)(const struct flowos_pm *, 
				    struct flowos_pmhdr *); 

/* Actual thread of a processing module 
   It is necessary to use the same PM in different flows */
struct pmodule {
  /* PM type */
  uint8_t type;
  /* Protocol it process */
  char protocol[NAMESIZ];
  /* Number of messages it handles */
  int msgcount;
  /* message handlers */
  flowos_pmmsg_handler *msg_handlers;
  /* The main function */
  pm_main_fn process;
  /* PM info */
  void *info; 
  /* position on the processing pipeline */
  int order;
  /* the flow this thread is attached to */
  struct flow *flow;
  /* head of the flow for this thread */
  struct streamp head;
  pthread_mutex_t head_lock;
  /* tail of the flow for this thread */
  struct streamp tail;
  pthread_mutex_t tail_lock;   
  /* message queue */
  struct msgqueue *mq;
  /* pthread as PM */   
  struct task *task;
  /* next to put in a list of PM threads */
  TAILQ_ENTRY(pmodule) list; 
};

typedef TAILQ_HEAD(, pmodule) pmodule_list_t;

struct flowos_pm * pm_init(struct task *task, struct flow *flow, uint8_t order);
void               pm_delete(struct flowos_pm *);
int                pm_is_empty(struct flowos_pm *);
void               pm_update_head(struct flowos_pm *pm);
struct streamp *   pm_move_head(struct flowos_pm *, struct streamp *);
struct streamp *   pm_set_head(struct flowos_pm *, struct packet *);
void               pm_dispatch_message(struct flowos_pm *pm, 
				       struct flowos_pmhdr *pmh);
void               pm_process_message(struct flowos_pm *pm);
int                pm_send_response(const struct flowos_pmhdr *, 
				    uint8_t, void *, size_t);

#define pm_is_last_stage(_pm) \
  (pipeline_get_stages((_pm)->flow->pipeline) == (_pm)->order + 1)

#define next_stage_pms(_pm) \
  (pipeline_get_pms((_pm)->flow->pipeline, (_pm)->order + 1))

#define is_same_level_pms(_src, _dst) \
  ((_src)->mod->protocol == (_dst)->mod->protocol)

#define pm_get_level(_pm) ((_pm)->head.level)

#endif /* _PMODULES_H_ */
