#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_ether.h>

#include "flowos.h"
#include "config.h"
#include "arp.h"

#define MAX_OPTLINE_LEN 1024
#define MAX_PROCLINE_LEN 1024

static const char *arp_file = "config/arp.conf";
static const char *route_file = "config/route.conf";

/*----------------------------------------*/
static int get_int_value(char* value) {
  int ret = 0;
  ret = strtol(value, (char**)NULL, 10);
  if (errno == EINVAL || errno == ERANGE)
    return -1;
  return ret;
}
/*----------------------------------------------------*/
static inline uint32_t mask_from_prefix(int prefix) {
  uint32_t mask = 0;
  uint8_t *mask_t = (uint8_t *)&mask;
  int i, j;
  
  for (i = 0; i <= prefix / 8 && i < 4; i++) {
    for (j = 0; j < (prefix - i * 8) && j < 8; j++) {
      mask_t[i] |= (1 << (7 - j));
    }
  }

  return mask;
}
/*----------------------------------------------------*/
static void flowos_enroll_route_table_entry(char *optstr) {
  char *daddr_s;
  char *prefix;
  char *dev;
  int ifidx;
  int ridx;
  int i;
  
  daddr_s = strtok(optstr, "/");
  prefix = strtok(NULL, " ");
  dev = strtok(NULL, "\n");
  
  assert(daddr_s != NULL);
  assert(prefix != NULL);
  assert(dev != NULL);
  
  ifidx = -1;
  for (i = 0; i < flowos.device_count; i++) {
    if (strcmp(dev, flowos.devices[i].name) != 0)
      continue;
    ifidx = flowos.devices[i].ifindex;
    break;
  }
  if (ifidx == -1) {
    printf("FlowOS: interface %s does not exist!\n", dev);
    exit(4);
  }  
  ridx = CONFIG.routes++;
  CONFIG.rtable[ridx].daddr = inet_addr(daddr_s);
  CONFIG.rtable[ridx].prefix = atoi(prefix);
  if (CONFIG.rtable[ridx].prefix > 32 || CONFIG.rtable[ridx].prefix < 0) {
    printf("FlowOS: prefix length should be between 0 - 32.\n");
    exit(4);
  }
  
  CONFIG.rtable[ridx].mask = mask_from_prefix(CONFIG.rtable[ridx].prefix);
  CONFIG.rtable[ridx].masked = 
    CONFIG.rtable[ridx].daddr & CONFIG.rtable[ridx].mask;
  CONFIG.rtable[ridx].nif = ifidx;
}
/*------------------------------------------------*/
static int config_routing_table_from_file()  {
#define ROUTES "ROUTES"
  
  FILE *fc;
  char optstr[MAX_OPTLINE_LEN];
  int i;
  
  printf("FlowOS: loading routing configurations from : %s\n", route_file);
  
  fc = fopen(route_file, "r");
  if (fc == NULL) {
    perror("fopen");
    printf("FlowOS: skips loading static routing table\n");
    return -1;
  }
  
  while (1) {
    char *iscomment;
    int num;
    
    if (fgets(optstr, MAX_OPTLINE_LEN, fc) == NULL)
      break;
    
    //skip comment
    iscomment = strchr(optstr, '#');
    if (iscomment == optstr)
      continue;
    if (iscomment != NULL)
      *iscomment = 0;
    
    if (!strncmp(optstr, ROUTES, sizeof(ROUTES) - 1)) {
      num = get_int_value(optstr + sizeof(ROUTES));
      if (num <= 0)
	break;
      
      for (i = 0; i < num; i++) {
	if (fgets(optstr, MAX_OPTLINE_LEN, fc) == NULL)
	  break;
	
	if (*optstr == '#') {
	  i -= 1;
	  continue;
	}
	flowos_enroll_route_table_entry(optstr);
      }
    }
  }
  
  fclose(fc);
  return 0;
}
/*--------------------------------------*/
void flowos_print_routing_table() {
  int i;
  uint8_t *da;
  uint8_t *m;
  uint8_t *md;
  
  /* print out process start information */
  printf("FlowOS: Routes\n");
  for (i = 0; i < CONFIG.routes; i++) {
    da = (uint8_t *)&CONFIG.rtable[i].daddr;
    m = (uint8_t *)&CONFIG.rtable[i].mask;
    md = (uint8_t *)&CONFIG.rtable[i].masked;
    printf("Destination: %u.%u.%u.%u/%d, Mask: %u.%u.%u.%u, "
		 "Masked: %u.%u.%u.%u, Route: eth%d\n", 
		 da[0], da[1], da[2], da[3], CONFIG.rtable[i].prefix, 
		 m[0], m[1], m[2], m[3], md[0], md[1], md[2], md[3], 
		 CONFIG.rtable[i].nif);
  }
  if (CONFIG.routes == 0)
    printf("(blank)\n");
  
  printf("----------------------------------------------------------"
	 "-----------------------\n");
}
/*------------------------------------------------------------------*/
static void parse_mac_address(unsigned char *haddr, char *haddr_str) {
  int i;
  char *str;
  unsigned int temp;
  
  str = strtok(haddr_str, ":");
  i = 0;
  while (str != NULL) {
    if (i >= ETH_ALEN) {
      printf("FlowOS: MAC address length exceeds %d!\n", ETH_ALEN);
      exit(4);
    }
    sscanf(str, "%x", &temp);
    haddr[i++] = temp;
    str = strtok(NULL, ":");
  }
  if (i < ETH_ALEN) {
    printf("FlowOS: MAC address length is less than %d!\n", ETH_ALEN);
    exit(4);
  }
}
/*-----------------------------------------------------------*/
static int parse_ip_address(uint32_t *ip_addr, char *ip_str) {
  if (ip_str == NULL) {
    *ip_addr = 0;
    return -1;
  }
  
  *ip_addr = inet_addr(ip_str);
  if (*ip_addr == INADDR_NONE) {
  printf("FlowOS: IP address is not valid %s\n", ip_str);
    *ip_addr = 0;
    return -1;
  }
  
  return 0;
}

/*----------------------------------------------------------------------------*/
int flowos_config_routing_table() {
  int i, ridx;
  unsigned int c;
  
  CONFIG.routes = 0;
  
  CONFIG.rtable = (struct route_table *)
    rte_calloc("route_table", MAX_DEVICES, sizeof(struct route_table), 0);
  if (! CONFIG.rtable) 
    rte_exit(EXIT_FAILURE, "FlowOS: failed to allocate routing table.");
  
  /* set default routing table */
  for (i = 0; i < CONFIG.eths_num; i ++) {
    ridx = CONFIG.routes++;
    CONFIG.rtable[ridx].daddr = CONFIG.eths[i].ip_addr & CONFIG.eths[i].netmask;
    
    CONFIG.rtable[ridx].prefix = 0;
    c = CONFIG.eths[i].netmask;
    while ((c = (c >> 1))){
      CONFIG.rtable[ridx].prefix++;
    }
    CONFIG.rtable[ridx].prefix++;
    
    CONFIG.rtable[ridx].mask = CONFIG.eths[i].netmask;
    CONFIG.rtable[ridx].masked = CONFIG.rtable[ridx].daddr;
    CONFIG.rtable[ridx].nif = flowos.devices[i].ifindex;
  }
  /* set additional routing table */
  config_routing_table_from_file();
  
  return 0;
}
/*-------------------------------------------------------------*/
int get_num_queues() {
  FILE *fp;
  char buf[MAX_PROCLINE_LEN];
  int queue_cnt;
  
  fp = fopen("/proc/interrupts", "r");
  if (! fp) {
    printf("FlowOS: failed to read data from /proc/interrupts!\n");
    return -1;
  }
  /* count number of NIC queues from /proc/interrupts */
  queue_cnt = 0;
  while (! feof(fp)) {
    if (fgets(buf, MAX_PROCLINE_LEN, fp) == NULL)
      break;
    /* "eth0-rx" is the keyword for counting queues */
    if (strstr(buf, "eth0-rx")) {
      queue_cnt++;
    }
  }
  fclose(fp);
  
  return queue_cnt;
}
/*--------------------------------------------------*/
void flowos_print_interface_info() {
  int i;
  /* print out process start information */
  printf("FlowOS: interfaces:\n");
  for (i = 0; i < CONFIG.eths_num; i++) {    
    uint8_t *da = (uint8_t *)&CONFIG.eths[i].ip_addr;
    uint8_t *nm = (uint8_t *)&CONFIG.eths[i].netmask;
    
    printf("name: %s, ifindex: %d, "
		 "hwaddr: %02X:%02X:%02X:%02X:%02X:%02X, "
		 "ipaddr: %u.%u.%u.%u, "
		 "netmask: %u.%u.%u.%u\n",
		 CONFIG.eths[i].dev_name, 
		 CONFIG.eths[i].ifindex, 
		 CONFIG.eths[i].haddr[0],
		 CONFIG.eths[i].haddr[1],
		 CONFIG.eths[i].haddr[2],
		 CONFIG.eths[i].haddr[3],
		 CONFIG.eths[i].haddr[4],
		 CONFIG.eths[i].haddr[5],
		 da[0], da[1], da[2], da[3],
		 nm[0], nm[1], nm[2], nm[3]);
  }
  printf("Number of NIC queues: %d\n", flowos.q_count);
  printf("----------------------------------------------------------"
	 "-----------------------\n");
}
/*--------------------------------------------------*/
static void enroll_arp_table_entry(char *optstr) {
  char *dip_s;		/* destination IP string */
  char *prefix_s;	/* IP prefix string */
  char *daddr_s;	/* destination MAC string */

  int prefix;
  uint32_t dip_mask;
  int idx;

  dip_s = strtok(optstr, "/");
  prefix_s = strtok(NULL, " ");
  daddr_s = strtok(NULL, "\n");
  
  assert(dip_s != NULL);
  assert(prefix_s != NULL);
  assert(daddr_s != NULL);
  
  prefix = atoi(prefix_s);
  
  if (prefix > 32 || prefix < 0) {
    printf("FlowOS: prefix length should be between 0 - 32.\n");
    return;
  }
  
  idx = CONFIG.arp.entries++;
  CONFIG.arp.entry[idx].prefix = prefix;
  parse_ip_address(&CONFIG.arp.entry[idx].ip, dip_s);
  parse_mac_address(CONFIG.arp.entry[idx].haddr, daddr_s);
  
  dip_mask = mask_from_prefix(prefix);
  CONFIG.arp.entry[idx].ip_mask = dip_mask;
  CONFIG.arp.entry[idx].ip_masked = CONFIG.arp.entry[idx].ip & dip_mask;
  
/*
  int i, cnt;
  cnt = 1;
  cnt = cnt << (32 - prefix);
  
  for (i = 0; i < cnt; i++) {
  idx = CONFIG.arp.entries++;
  CONFIG.arp.entry[idx].ip = htonl(ntohl(ip) + i);
  memcpy(CONFIG.arp.entry[idx].haddr, haddr, ETH_ALEN);
  }
*/
}
/*---------------------------------------------------------*/
int flowos_config_arp_table() {
#define ARP_ENTRY "ARP_ENTRY"
  FILE *fc;
  char optstr[MAX_OPTLINE_LEN];
  int numEntry = 0;
  int hasNumEntry = 0;
  
  printf("FlowOS: loading ARP table from : %s\n", arp_file);  
  fc = fopen(arp_file, "r");
  if (fc == NULL) {
    perror("fopen");
    printf("FlowOS: skips loading static ARP table\n");
    return -1;
  }
  flowos_init_arp_table();
  while (1) {
    char *p;
    char *temp;    
    if (fgets(optstr, MAX_OPTLINE_LEN, fc) == NULL)
      break;
    //printf("Processing: %s", optstr);
    p = optstr;
    
    // skip comment
    if ((temp = strchr(p, '#')) != NULL)
      *temp = 0;
    // remove front and tailing spaces
    while (*p && isspace((int)*p))
      p++;
    temp = p + strlen(p) - 1;
    while (temp >= p && isspace((int)*temp))
      *temp = 0;
    if (*p == 0) /* nothing more to process? */
      continue;
    
    if (!hasNumEntry && strncmp(p, ARP_ENTRY, sizeof(ARP_ENTRY)-1) == 0) {
      numEntry = get_int_value(p + sizeof(ARP_ENTRY));
      if (numEntry <= 0) {
	rte_exit(EXIT_FAILURE, "FlowOS: invalid ARP entry in arp.conf: %s\n", p);
      }
#if 0
      CONFIG.arp.entry = (struct arp_entry *)
	rte_calloc("arp_entry", numEntry + MAX_ARPENTRY, sizeof(struct arp_entry), 0);
      if (CONFIG.arp.entry == NULL) {
	rte_exit(EXIT_FAILURE, "FlowOS: invalid ARP entry in arp.conf: %s\n", p);
      }
#endif
      hasNumEntry = 1;
    } 
    else {
      if (numEntry <= 0) {
	rte_exit(EXIT_FAILURE, 
		 "Error in arp.conf: more entries than "
		 "are specifed, entry=%s\n", p);
      }
      printf("FlowOS: setting ARP entry: %s, count=%d\n", p, numEntry);
      enroll_arp_table_entry(p);
      numEntry--;
    }
  }
  
  fclose(fc);
  return 0;
}
/*-------------------------------------------------*/
static int parse_tcp_config(char *line) {
  int idx;
  char optstr[MAX_OPTLINE_LEN];
  char *p, *q, *p1, *q1;
  
  strncpy(optstr, line, MAX_OPTLINE_LEN - 1);
  
  p = strtok(optstr, " \t=");
  if (p == NULL) {
    printf("FlowOS: no option name found for the line: %s\n", line);
    return -1;
  }
  
  q = strtok(NULL, " \t=");
  if (q == NULL) {
    printf("FlowOS: no option value found for the line: %s\n", line);
    return -1;
  }
  /* Interface IP address and netmask configuration */
  if (strcmp(p, "eth_index") == 0) {
    idx = atoi(q);
    printf("ipconfig: %s=%d\n", p, idx);
    p = strtok(NULL, " \t=");
    if (p == NULL) {
      printf("FlowOS: option eth_index requires ip_addr and netmask: %s\n", line);
      return -1;
    }  
    printf("ipconfig: %s\n", p);
    q = strtok(NULL, " \t=");
    if (q == NULL) {
      printf("FlowOS: no value found for option %s for the line: %s\n", p, line);
      return -1;
    }
    printf("ipconfig: %s\n", q);
    p1 = strtok(NULL, " \t=");
    if (p1 == NULL) {
      printf("FlowOS: option eth_index requires ip_addr and netmask: %s\n", line);
      return -1;
    }  
    printf("ipconfig: %s\n", p1);
    q1 = strtok(NULL, " \t=");
    if (q1 == NULL) {
      printf("FlowOS: no value found for option %s for the line: %s\n", p, line);
      return -1;
    }
    printf("ipconfig: %s\n", q1);
    if (strcmp(p, "ip_addr") == 0 && strcmp(p1, "netmask") == 0) {
      if (parse_ip_address(&flowos.devices[idx].ip_addr, q) == -1) {
	printf("FlowOS: invalid IP address: %s on line: %s\n", q, line);
	return -1;
      }
      if (parse_ip_address(&flowos.devices[idx].netmask, q1) == -1) {
	printf("FlowOS: invalid netmask: %s on line: %s\n", q1, line);
	return -1;
      }
    }
    else if (strcmp(p, "netmask") == 0 && strcmp(p1, "ip_addr") == 0)  {
      if (parse_ip_address(&flowos.devices[idx].ip_addr, q1) == -1) {
	printf("FlowOS: invalid IP address: %s on line: %s\n", q1, line);
	return -1;
      }
      if (parse_ip_address(&flowos.devices[idx].netmask, q) == -1) {
	printf("FlowOS: invalid netmask: %s on line: %s\n", q, line);
	return -1;
      }
    }
    else {  
      printf("FlowOS: invalid IP configuration for line: %s\n", line);
      return -1;
    }
  }
  else if (strcmp(p, "num_cores") == 0) {
    CONFIG.num_cores = atoi(q);
    if (CONFIG.num_cores <= 0) {
      printf("FlowOS: number of cores should be larger than 0.\n");
      return -1;
    }
    if (CONFIG.num_cores > flowos.cpu_count) {
      printf("FlowOS: number of cores should be smaller than "
		   "# physical CPU cores.\n");
      return -1;
    }
  } 
  else if (strcmp(p, "max_concurrency") == 0) {
    CONFIG.max_concurrency = atoi(q);
    if (CONFIG.max_concurrency < 0) {
      printf("FlowOS: the maximum concurrency should be larger than 0.\n");
      return -1;
    }
  } 
  else if (strcmp(p, "max_num_buffers") == 0) {
    CONFIG.max_num_buffers = atoi(q);
    if (CONFIG.max_num_buffers < 0) {
      printf("FlowOS: the maximum # buffers should be larger than 0.\n");
      return -1;
    }
  } 
  else if (strcmp(p, "rcvbuf") == 0) {
    CONFIG.rcvbuf_size = atoi(q);
    if (CONFIG.rcvbuf_size < 64) {
      printf("FlowOS: receive buffer size should be larger than 64.\n");
      return -1;
    }
  } 
  else if (strcmp(p, "sndbuf") == 0) {
    CONFIG.sndbuf_size = atoi(q);
    if (CONFIG.sndbuf_size < 64) {
      printf("FlowOS: send buffer size should be larger than 64.\n");
      return -1;
    }
  } 
  else if (strcmp(p, "tcp_timeout") == 0) {
    CONFIG.tcp_timeout = atoi(q);
    if (CONFIG.tcp_timeout > 0) {
      CONFIG.tcp_timeout = SEC_TO_USEC(CONFIG.tcp_timeout) / TIME_TICK;
    }
  } 
  else if (strcmp(p, "tcp_timewait") == 0) {
    CONFIG.tcp_timewait = atoi(q);
    if (CONFIG.tcp_timewait > 0) {
      CONFIG.tcp_timewait = SEC_TO_USEC(CONFIG.tcp_timewait) / TIME_TICK;
    }
  } 
  else if (strcmp(p, "stat_print") == 0) {
    int i;
    
    for (i = 0; i < CONFIG.eths_num; i++) {
      if (strcmp(CONFIG.eths[i].dev_name, q) == 0) {
	CONFIG.eths[i].stat_print = 1; // TRUE
      }
    }
  } 
  else {
    printf("FlowOS: unknown option type: %s\n", line);
    return -1;
  }
  
  return 0;
}
/*---------------------------------------------*/
int flowos_config_tcp(char *fname) {
  FILE *fp;
  char optstr[MAX_OPTLINE_LEN];
  
  printf("----------------------------------------------------------"
	       "-----------------------\n");
  printf("FlowOS: loading mTCP configuration from : %s\n", fname);
  
  fp = fopen(fname, "r");
  if (fp == NULL) {
    perror("fopen");
    printf("FlowOS: failed to load configuration file: %s\n", fname);
    return -1;
  }  
  /* set default configuration */
  CONFIG.num_cores = flowos.cpu_count;
  CONFIG.max_concurrency = 100000;
  CONFIG.max_num_buffers = 100000;
  CONFIG.rcvbuf_size = 8192;
  CONFIG.sndbuf_size = 8192;
  CONFIG.tcp_timeout = TCP_TIMEOUT;
  CONFIG.tcp_timewait = TCP_TIMEWAIT;
  
  while (1) {
    char *p;
    char *temp;
    
    if (fgets(optstr, MAX_OPTLINE_LEN, fp) == NULL)
      break;
    
    p = optstr;
    
    // skip comment
    if ((temp = strchr(p, '#')) != NULL)
      *temp = 0;
    // remove front and tailing spaces
    while (*p && isspace((int)*p))
      p++;
    temp = p + strlen(p) - 1;
    while (temp >= p && isspace((int)*temp))
      *temp = 0;
    if (*p == 0) /* nothing more to process? */
      continue;
    
    if (parse_tcp_config(p) < 0)
      return -1;
  }
  
  fclose(fp);
  
  return 0;
}
/*------------------------------------------------*/
void flowos_print_tcp_config() {
  int i;
  
  printf("FlowOS: TCP configurations:\n");
  printf("Number of CPU cores available: %d\n", flowos.cpu_count);
  printf("Number of CPU cores to use: %d\n", CONFIG.num_cores);
  printf("Maximum number of concurrency per core: %d\n", 
	       CONFIG.max_concurrency);
  
  printf("Maximum number of preallocated buffers per core: %d\n", 
	       CONFIG.max_num_buffers);
  printf("Receive buffer size: %d\n", CONFIG.rcvbuf_size);
  printf("Send buffer size: %d\n", CONFIG.sndbuf_size);
	
  if (CONFIG.tcp_timeout > 0) {
    printf("TCP timeout seconds: %d\n", 
		 USEC_TO_SEC(CONFIG.tcp_timeout * TIME_TICK));
  } 
  else {
    printf("TCP timeout check disabled.\n");
  }
  printf("TCP timewait seconds: %d\n", 
	       USEC_TO_SEC(CONFIG.tcp_timewait * TIME_TICK));
  printf("NICs to print statistics:");
  for (i = 0; i < CONFIG.eths_num; i++) {
    if (CONFIG.eths[i].stat_print) {
      printf(" %s", CONFIG.eths[i].dev_name);
    }
  }
  printf("\n");
  printf("----------------------------------------------------------"
    "-----------------------\n");
}
/*--------------------------------------------------------------*/
