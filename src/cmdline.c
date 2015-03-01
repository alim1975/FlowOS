#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <pthread.h>
#include <netinet/in.h>

#include "messageq.h"
#include "flow.h"
#include "pipeline.h"
#include "pmodule.h"
#include "cmdline.h"

/* Command-Line Client PID */
static int cli_pid;
/* Message queue for Client commands */
struct msgqueue *flowos_cmdq;

extern void           flowos_get_pms(char *buff);
extern void           flowos_get_flows(char *buff);

inline void cmdline_dispatch_message(struct flowos_msghdr *msg) {
  msgqueue_insert(flowos_cmdq, msg);
}

struct flowos_msghdr *
flowos_new_message(const void *msg, size_t len, u8 type, u8 flags) {
  size_t size;
  struct flowos_msghdr *mh;
  size = (msg == NULL) ? sizeof(*mh) : sizeof(*mh) + len;
  mh = rte_malloc("flowos_msghdr", size, 0);
  if(! mh){
    printf("flowos_new_message(): failed to allocate memory\n");
    return NULL;
  }
  mh->type = type;
  mh->flags = flags;
  if(msg) memcpy(mh->msg, msg, len);
  mh->size = htons(size);
  mh->daddr.s_addr = in_aton("127.0.0.1");
  mh->saddr.s_addr = in_aton("127.0.0.1");

  return mh;
}

int flowos_send_response(const struct flowos_msghdr *req, 
			 u8 flags, char *msg, size_t len) {
  int rc;
  struct flowos_msghdr *res;
  res = flowos_new_message(msg, len, req->type, flags);
  if(! res){
    printf("flowos_send_response(): failed to "
	   "allocate memory for response\n");
    return -1;
  }
  res->flags |= FLOWOS_RESPONSE; 
  res->seq = req->seq;
  res->daddr.s_addr = req->saddr.s_addr;
  res->saddr.s_addr = req->daddr.s_addr;
  if (flowos_send_message(res) != 0) 
    printf("flowos_send_response(): Failed to send ACK\n"); 
  //rte_free(res);

  return rc;
}

static struct flowos_pmhdr *
pm_new_response(const struct flowos_pmhdr *req, 
		u8 flags, void *msg, size_t len) {
  size_t size;
  struct flowos_pmhdr *res;
  size = (msg == NULL) ? sizeof(*res) : sizeof(*res) + len;
  res = rte_malloc("flowos_pmhdr", size, 0);
  if(! res){
    print("pm_new_response(): failed to allocate "
	   "memory for response\n");
    return NULL;
  }
  /* response header */
  res->ctrl.type = req->ctrl.type;
  res->ctrl.seq = req->ctrl.seq;
  res->ctrl.flags = flags;
  res->ctrl.flags |= FLOWOS_RESPONSE;
  res->ctrl.saddr = req->ctrl.daddr;
  res->ctrl.daddr = req->ctrl.saddr;
  res->command = req->command;
  strcpy(res->spm, req->dpm);
  strcpy(res->dpm, req->spm);
  strcpy(res->sflow, req->dflow);
  strcpy(res->dflow, req->sflow);
  if(msg) memcpy(res->msg, msg, len);
  res->ctrl.size = htons(size);
  
  return res;
}

static int __pm_send_response(const struct flowos_pmhdr *req, 
			      u8 flags, void *msg, size_t len) {
  int rc;
  struct flowos_pmhdr *res;
  res = pm_new_response(req, flags, msg, len);
  if(! res){ 
    printf("__pm_send_response(): failed to "
	   "create response message\n");
    return -1;
  }
  rc = flowos_send_message((struct flowos_msghdr *)res);  
  if(rc < 0) printf("flowos_send_response(): Failed to send ACK\n");  
  //rte_kfree(res);

  return rc;
}

int pm_send_response(const struct flowos_pmhdr *req, 
		     u8 flags, void *msg, size_t len) {
  struct flowos_pmhdr *res;
  res = pm_new_response(req, flags, msg, len);
  if (! res) {   
    printf("pm_send_response(): failed "
	   "to create response message\n");
    return -1;
  }
  cmdline_dispatch_message((struct flowos_msghdr *)res);

  return 0;
}

/* FlowOS command handlers */
static int flowos_login_handler(const struct flowos_msghdr *req) {
  char msg[80];
  sprintf(msg, "FlowOS: Login handler not implemented yet");
  flowos_send_response(req, FLOWOS_FAILURE, msg, strlen(msg));

  return 0;
}

static int flowos_logout_handler(const struct flowos_msghdr *req) {
  char msg[80];
  sprintf(msg, "FlowOS: Logout handler not implemented yet");
  flowos_send_response(req, FLOWOS_FAILURE, msg, strlen(msg));

  return 0;
}

static int flowos_create_flow_handler(const struct flowos_msghdr *req) {
  int len;
  char buff[80];
  struct flow *flow;
  struct create_flow_msg *msg = (struct create_flow_msg *)req;

  if (ntohs(req->size) < sizeof(*msg)) {
    strcpy(buff, "FlowOS: Invalid create flow command");
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
    return 0;
  }
  if (flowos_find_flow(msg->name)) {
    sprintf(buff, "FlowOS: Flow [%s] already exists.", msg->name);
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
    return 0;
  }
  /* Create the flow */ 
  if ((flow = flow_create(&msg->fid, msg->name)) == NULL) {
    strcpy(buff, "FlowOS: Failed to create new flow");
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
  }
  else {
    len = ntohs(req->size) - sizeof(*msg);
    memcpy(buff, msg->protos, len);
    buff[len] = '\0';
    flow_set_protocols(flow, buff);
    flowos_send_response(req, FLOWOS_SUCCESS, NULL, 0);
  }  
  return 0;
}

static int flowos_delete_flow_handler(const struct flowos_msghdr *req) {
  int len;
  char name[32], buff[80];
 
  if (ntohs(req->size) <= sizeof(*req)) {
    sprintf(buff, "FlowOS: invalid delete flow message");
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
    return 0;
  }
  len = ntohs(req->size) - sizeof(*req);
  strncpy(name, req->msg, len);
  name[len] = '\0';  
  if (flowos_remove_flow(name) != 0) {
    sprintf(buff, "FlowOS: Failed to delete flow: %s", name);
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
  }
  else {
    flowos_send_response(req, FLOWOS_SUCCESS, NULL, 0);
  }
  return 0;
}

static int flowos_update_flow_handler(const struct flowos_msghdr *req) {
  char buff[80];
  sprintf(buff, "FlowOS: Update handler not implemented yet");
  flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));

  return 0;
}

static int flowos_migrate_flow_handler(const struct flowos_msghdr *req) {
  char buff[80];
  sprintf(buff, "FlowOS: Migrate handler not implemented yet");
  flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));

  return 0;
}

static int flowos_create_pipeline_handler(const struct flowos_msghdr *req)
{
  int len;
  struct flow *flow;
  char name[32], buff[80];
  struct create_pipeline_msg *msg = (struct create_pipeline_msg *)req;

  if (ntohs(req->size) < sizeof(*msg)) {
    sprintf(buff, "FlowOS: invalide create pipe message");
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
    return 0;
  }
  len = ntohs(req->size) - sizeof(*msg);
  memcpy(name, msg->name, len);
  name[len] = '\0';
  if ((flow = flowos_find_flow(name)) == NULL) {
    sprintf(buff, "FlowOS: Failed to locate flow [%s]", name);
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
    return 0;
  }
  flow->pipeline = pipeline_create(msg->stages);
  if (flow->pipeline == NULL) {
    sprintf(buff, "FlowOS: Failed to create pipeline for flow [%s]", name);
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
  }
  else {
    flowos_send_response(req, FLOWOS_SUCCESS, NULL, 0);
  }
  return 0;
}

static int flowos_delete_pipeline_handler(const struct flowos_msghdr *req) {
  char buff[80];
  sprintf(buff, "FlowOS: Delete pipeline handler not implemented yet");
  flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
 
  return 0;
}

static int flowos_attach_pm_handler(const struct flowos_msghdr *req) {
  int rc;
  u8 position;
  struct flow *flow;
  struct task *task;
  char buff[80], modname[NAMESIZ], flowname[NAMESIZ];
  struct attach_pm_msg *msg = (struct attach_pm_msg *)req;
  strcpy(modname, msg->taskname);
  strcpy(flowname, msg->flowname);
  position = msg->pos;
  flow = flowos_find_flow(flowname);
  if (! flow) {
    sprintf(buff, "FlowOS: Flow [%s] does not exist", flowname);
    printk(KERN_INFO "%s\n", buff);
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
    return 0;
  }
  task = task_create(modname);
  if (! task) {
    printf("Failed to load kernel module: %s", modname);
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
    return 0;
  }
  /* instantiate a thread of kmod and attach to flow */
  rc = flow_attach_pm(flow, task, position);
  if (rc < 0) {
    printf("FlowOS: failed to attach PM [%s] to flow [%s]", 
	    modname, flowname);
    flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));
  }
  else {
    flowos_send_response(req, FLOWOS_SUCCESS, NULL, 0);    
  }
  return 0;
}

static int flowos_detach_pm_handler(const struct flowos_msghdr *req) {
  char buff[80];
  sprintf(buff, "FlowOS: Detach PM handler not implemented yet");
  flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));

  return 0;
}

/* TODO: use some nice structure */
static int flowos_query_handler(const struct flowos_msghdr *req) {
  int len;
  char *ptr, msg[80], buff[256];
  ptr = buff;
  flowos_get_flows(msg);
  strcpy(ptr, msg);
  len = strlen(msg); 
  strcat(ptr, "\n");
  len++;
  flowos_get_pms(msg);
  strcat(ptr, msg);
  len += strlen(msg);
  strcat(ptr, "\n");
  len++;
  sprintf(msg, "FlowOS processed %lu packets", flowos_get_pktprocessed());
  strcat(ptr, msg);
  len += strlen(msg);
  strcat(ptr, "\n");
  ptr++;
  sprintf(msg, "FlowOS: drops %lu packets", flowos_get_pktdropped());
  strcat(ptr, msg);
  len += strlen(msg);
  flowos_send_response(req, FLOWOS_SUCCESS, buff, len);

  return 0;
}

static int flowos_query_flow_handler(const struct flowos_msghdr *req) {
  char buff[80];
  sprintf(buff, "FlowOS: show status --flow <flow-name> NOT implemented yet");
  flowos_send_response(req, FLOWOS_FAILURE, buff, strlen(buff));

  return 0;
}

static int flowos_pm_message_handler(const struct flowos_pmhdr *req) {
  struct flow *flow;
  struct flowos_pm *pm;
  struct flowos_pmhdr *res;
  /* unlikely */
  if (ntohs(req->ctrl.size) < sizeof(*req)) {
    printf("FlowOS: Invalid PM message\n");
    return -1;
  }
  flow = flowos_find_flow((char *)req->dflow);
  if (! flow) { 
    printf("FlowOS: Flow [%s] not found\n", req->dflow);
    return -1;
  }
  if (! flow->pipeline) {
    printf("FlowOS: Pipeline of flow [%s] is empty\n", req->dflow);
    return -1;
  }
  pm = pipeline_find_pm(flow->pipeline, req->dpm);
  if (! pm) {
    printf("FlowOS: PM [%s] not found\n", req->dpm);
    return -1;
  }
  res = kmalloc(ntohs(req->ctrl.size), GFP_ATOMIC);
  if (! res) {
    printf("FlowOS: failed to allocate memory\n");
    return -1;
  }
  memcpy(res, req, ntohs(req->ctrl.size));
  /* enqueue message for the destination PM */  
  pm_dispatch_message(pm, res);

  return 0;
}

flowos_cmd_handler flowos_cmd_handlers[] =  {
 [FLOWOS_LOGIN] = flowos_login_handler,
 [FLOWOS_LOGOUT] = flowos_logout_handler,
 [FLOWOS_CREATE_FLOW] = flowos_create_flow_handler,
 [FLOWOS_DELETE_FLOW] = flowos_delete_flow_handler,
 [FLOWOS_UPDATE_FLOW] = flowos_update_flow_handler,
 [FLOWOS_MIGRATE_FLOW] = flowos_migrate_flow_handler,
 [FLOWOS_CREATE_PIPELINE] = flowos_create_pipeline_handler,
 [FLOWOS_DELETE_PIPELINE] = flowos_delete_pipeline_handler,
 [FLOWOS_ATTACH_PM] = flowos_attach_pm_handler,
 [FLOWOS_DETACH_PM] = flowos_detach_pm_handler,
 [FLOWOS_QUERY] = flowos_query_handler,
 [FLOWOS_QUERY_FLOW] = flowos_query_flow_handler,
};

int flowos_command_handler(struct msgqueue *cmdq) {
  int rc;
  char buff[80];
  struct flowos_msghdr *cmd;  
  struct flowos_pmhdr *pmh;

  while (1) {
    set_current_state(TASK_INTERRUPTIBLE); 
    if(msgqueue_is_empty(cmdq)){      
      schedule();					
      if(kthread_should_stop())				
	break;
      set_current_state(TASK_RUNNING);			
    }
    /* process all messages */
    while((cmd = (struct flowos_msghdr *)msgqueue_remove(cmdq))){
      if(cmd->type >= FLOWOS_MSGCOUNT){
	sprintf(buff, "FlowOS: failed to dispatch PM message");	      
	flowos_send_response(cmd,  FLOWOS_FAILURE, buff, strlen(buff));
	kfree(cmd);
	continue;
      }
      if(ip_dev_find(&init_net, cmd->daddr.s_addr)){ /* for this host */
	if(cmd->type == FLOWOS_PMMSG){ /* PM message */
	  pmh = (struct flowos_pmhdr *)cmd;
	  if(pmh->dpm[0] == '\0'){ /* for CLI from PM */
	    nl_send_response(cmd, cli_pid);
	  }
	  else{ /* for PM */
	    rc = flowos_pm_message_handler(pmh); /* dispatch to PM */
	    if(rc < 0){ /* failed to dispatch to PM */
	      strcpy(buff, "FlowOS: failed to dispatch PM message");	      
	      __pm_send_response(pmh, FLOWOS_FAILURE, buff, strlen(buff)); 	      
	    }
	  }
	}
	else{ /* FlowOS message */
	  if(cmd->flags & FLOWOS_RESPONSE){ /* for CLI from remote hosts */
	    nl_send_response(cmd, cli_pid);
	  }
	  else{ /* for FlowOS */
	    rc = (*flowos_cmd_handlers[cmd->type])(cmd); /* invoke actual command handler */      
	    if(rc < 0){ /* command handler returns ERROR */
	      strcpy(buff, "FlowOS: failed to process FlowOS message");
	      flowos_send_response(cmd, FLOWOS_FAILURE, buff, strlen(buff));
	    }
	  }
	}
      }
      else{ /* for remote host */
	rc = flowos_send_message(cmd); 
	if(rc < 0){
	  strcpy(buff, "FlowOS: Failed to forward the message");
	  flowos_send_response(cmd, FLOWOS_FAILURE, buff, strlen(buff));
	}
      }
      kfree(cmd);
    } /* msg queue */
  } /* main loop */ 
  return 0;
}

/* Process FlowOS commands received via NetLink interface */
void flowos_netlink_rcv(struct sk_buff *skb)
{
  char msg[80];
  int flags;
  size_t len, size;
  struct flowos_msghdr *cmd;
  struct nlmsghdr *nlmsg = NULL;

  flags = 0;
  len = skb->len;  
  if(len < sizeof(*nlmsg)){
    sprintf(msg, "nl_rcv(): Invalid FlowOS command");
    goto error;
  }
  nlmsg = nlmsg_hdr(skb);
  size = nlmsg->nlmsg_len;
  flags = nlmsg->nlmsg_flags;
  cli_pid = nlmsg->nlmsg_pid;
  if(size < sizeof(*nlmsg) || len < size){
    strcpy(msg, "FlowOS: Too short to be a FlowOS command");
    goto error;
  }
  cmd = kmalloc(size, GFP_ATOMIC);
  if(! cmd){
    strcpy(msg, "FlowOS: Unable to allocate memory for NetLink command");
    goto error;
  }
  memcpy(cmd, NLMSG_DATA(nlmsg), size);
  cmdline_dispatch_message(cmd);
  /* ACK requested */
  if(flags & NLM_F_ACK)
    netlink_ack(skb, nlmsg, 0);
  return;
 error:
  cmd = flowos_new_message(msg, strlen(msg), 0, FLOWOS_FAILURE);
  if(! cmd){
    printk(KERN_INFO "nl_rcv(): failed to allocate memory\n");   
  }
  else{
    nl_send_response(cmd, cli_pid);
    kfree(cmd);
  }
}

int cmdline_init(void)
{
  struct netlink_kernel_cfg nl_cfg = {
    .input = flowos_netlink_rcv,
    .flags = NL_CFG_F_NONROOT_RECV,
  };

 /* cli_nlsk = netlink_kernel_create(&init_net,
				   NETLINK_FLOWOS,
				   1,
				   flowos_netlink_rcv,
				   NULL,
				   THIS_MODULE); */

  cli_nlsk = netlink_kernel_create(&init_net,
				   NETLINK_FLOWOS,
				   &nl_cfg);

  if(! cli_nlsk){
    printk(KERN_INFO "FlowOS: Failed to initialize NetLink socket\n");
    return -ENOMEM;
  }
  // netlink_set_nonroot(NETLINK_FLOWOS, NL_CFG_F_NONROOT_RECV);

  /* FlowOS command handler thread */
  flowos_cmdq = msgqueue_create();
  if(flowos_cmdq == NULL){
    printk(KERN_INFO "FlowOS: failed to create command queue\n");
    return -ENOMEM;
  }
  flowos_cmdhandler = kthread_run((thread_fn)flowos_command_handler, 
				  flowos_cmdq, "flowos_cmdq");
  if(! flowos_cmdhandler){
    printk(KERN_INFO "FlowOS: Failed to initialize command handler\n");
    netlink_kernel_release(cli_nlsk);
    cli_nlsk = NULL;
    msgqueue_delete(flowos_cmdq);
    return -ENOMEM;
  }
  return 0;
}

void cmdline_close(void)
{
  printk(KERN_INFO "FlowOS: closing command handler\n");
  kthread_stop(flowos_cmdhandler);  
  flowos_cmdhandler = NULL;
  msgqueue_delete(flowos_cmdq);
  flowos_cmdq = NULL;
  printk(KERN_INFO "FlowOS: closing NetLink socket\n");
  if(cli_nlsk)
    netlink_kernel_release(cli_nlsk);
  cli_nlsk = NULL;
}
