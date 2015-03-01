#ifndef __CMDLINE_H__
#define __CMDLINE_H__

#include <stdint.h>
#include <netinet/in.h>

#include <rte_mbuf.h>

#include "hashtable.h"
#include "flowid.h"

#ifndef NAMESIZ
#define NAMESIZ 16
#endif

#define UDP_ENCAP_PORT 54325
#define UDP_ENCAP_MAGIC	0x61114EDA
#define NETLINK_FLOWOS 17
#define NLMSG_FLOWOS NLMSG_MIN_TYPE

#define FLOWOS_LOGIN           0
#define FLOWOS_LOGOUT          1
#define FLOWOS_CREATE_FLOW     2
#define FLOWOS_DELETE_FLOW     3  
#define FLOWOS_UPDATE_FLOW     4
#define FLOWOS_MIGRATE_FLOW    5
#define FLOWOS_CREATE_PIPELINE 6
#define FLOWOS_DELETE_PIPELINE 7
#define FLOWOS_ATTACH_PM       8
#define FLOWOS_DETACH_PM       9
#define FLOWOS_QUERY           10
#define FLOWOS_QUERY_FLOW      11  
#define FLOWOS_PMMSG           12
#define FLOWOS_MSGCOUNT        13

#define FLOWOS_SUCCESS  1
#define FLOWOS_FAILURE  2
#define FLOWOS_REQUEST  4
#define FLOWOS_RESPONSE 8

#define XSTR(S) TOSTR(S)
#define TOSTR(S) #S
#define STRCAT_(X, Y) X ## Y
#define STRCAT(X, Y) STRCAT_(X, Y)
#define STRCAT4(A, B, C, D) STRCAT(A, STRCAT(B, STRCAT(C, D))) 

#define CT_ASSERT(EXP) enum {STRCAT(assert_line_, __LINE__) = 1/(!!(EXP)) }

#define FH_SET_FLAGS(value) MSG->flags |= value
#define FH_GET_FLAGS(flags) MSG->flags
#define FH_SET_MSGTYPE(msgid) MSG->type = msgid
#define FH_GET_MSGTYPE() MSG->type
#define FH_SET_MSGLEN(len) MSG->size = htons(sizeof(*MSG) + len)
#define FH_GET_MSGLEN() (ntohs(MSG->size) - sizeof(*MSG))
#define FH_SET_SADDR(ip) MSG->saddr = ip
#define FH_GET_SADDR() MSG->saddr
#define FH_SET_DADDR(ip) MSG->daddr = ip
#define FH_GET_DADDR() MSG->daddr
#define FH_SET_MSG(buff, len) memcpy(MSG->msg, buff, len)
#define FH_GET_MSG() MSG->msg

#define PMH_SET_COMMAND(cmd) MSG->command = cmd
#define PMH_GET_COMMAND() MSG->command
#define PMH_SET_SPM(name) strcpy(MSG->spm, name)
#define PMH_SET_DPM(name) strcpy(MSG->dpm, name)
#define PMH_SET_SFLOW(name) strcpy(MSG->sflow, name)
#define PMH_SET_DFLOW(name) strcpy(MSG->dflow, name)
#define PMH_SET_MSG(buff, len) memcpy(MSG->msg, buff, len)
#define PMH_GET_MSG() (MSG->msg)

#define PMH_SET_FLAGS(value) MGS->ctrl.flags |= value
#define PMH_GET_FLAGS() (MSG->ctrl.flags)
#define PMH_SET_MSGTYPE(msgid) MSG->ctrl.type = msgid
#define PMH_GET_MSGTYPE() MSG->ctrl.type
#define PMH_SET_MSGLEN(len) MSG->ctrl.size = htons(sizeof(*MSG) + len)
#define PMH_GET_MSGLEN() (ntohs(MSG->ctrl.size) - sizeof(*MSG))
#define PMH_SET_SADDR(ip) MSG->ctrl.saddr = ip
#define PMH_GET_SADDR() MSG->ctrl.saddr
#define PMH_SET_DADDR(ip) MSG->ctrl.daddr = ip
#define PMH_GET_DADDR() MSG->ctrl.daddr

#define CLI_DEF_PMCMD_PARSER(msgid) \
int STRCAT4(parse_, FLOWOS_PMNAME, _msg_, msgid) \
(int argc, char **argv, struct flowos_pmhdr *MSG)

#define CLI_DEF_PMMSG_HANDLER() \
  void STRCAT(FLOWOS_PMNAME, _print_response)(struct flowos_pmhdr *MSG)

#define CLI_REG_PMCOMMANDS() \
  void STRCAT(FLOWOS_PMNAME, _register_commands)(struct hashtable *HT)

#define CLI_MAP_COMMAND(msgid, cmdstring) \
  hashtable_insert(HT, cmdstring, STRCAT4(parse_, FLOWOS_PMNAME, _msg_, msgid))

/*
struct udp_encap {
  int magic;
  struct sock *sk_parent; 
  struct sock *sk;
  void (*old_sk_destruct)(struct sock *);
};
*/

struct flowos_msghdr {
  uint8_t type;
  uint8_t flags;
  uint16_t seq;
  uint16_t size;
  struct in_addr saddr;
  struct in_addr daddr;
  char msg[0];
};

struct create_flow_msg {
  struct flowos_msghdr ctrl;
  struct flowid fid;
  char name[NAMESIZ];
  char protos[0];
};

struct create_pipeline_msg {
  struct flowos_msghdr ctrl;
  uint8_t stages;
  char name[0];
};

struct attach_pm_msg {
  struct flowos_msghdr ctrl;
  uint8_t pos;
  char modname[NAMESIZ];
  char flowname[NAMESIZ];
};

struct flowos_pmhdr {
  struct flowos_msghdr ctrl;
  uint8_t command;
  char sflow[NAMESIZ];
  char spm[NAMESIZ];
  char dflow[NAMESIZ];
  char dpm[NAMESIZ];
  char msg[0]; 
};

//typedef int (*thread_fn)(void *);

typedef int (*flowos_cmd_handler)(const struct flowos_msghdr *); 

extern unsigned long flowos_get_pktprocessed(void);
extern unsigned long flowos_get_pktdropped(void);

extern int           flowos_send_message(struct flowos_msghdr *);

int                  nl_send_response(struct flowos_msghdr *msg, int peer);

int                 cmdline_init(void);
void                cmdline_close(void);
void                cmdline_dispatch_message(struct flowos_msghdr *);

#endif /* __CMDLINE_H__ */
