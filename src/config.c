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

#include "config.h"
#include "arp.h"
#include "flowos.h"

#define MAX_OPTLINE_LEN 1024
#define MAX_PROCLINE_LEN 1024

/*----------------------------------------*/
static inline int get_int_value(char* value) {
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
	printf("FlowOS: number of devices %d\n", flowos.device_count);
  for (i = 0; i < flowos.device_count; i++) {
		printf("Name of device %d is %s\n", i, flowos.devices[i].name);
    if (strcmp(dev, flowos.devices[i].name) != 0)
      continue;
		if (! flowos.devices[i].configured) {
			printf("FlowOS error: interface eth%d is not configured\n", i);
			exit(1);
		}
    ifidx = i; //flowos.devices[i].ifindex;
    break;
  }

  if (ifidx == -1) {
    printf("FlowOS: interface %s does not exist!\n", dev);
    exit(4);
  }
  ridx = flowos.routes++;
  flowos.rt[ridx].daddr = inet_addr(daddr_s);
  flowos.rt[ridx].prefix = atoi(prefix);
  if (flowos.rt[ridx].prefix > 32 || flowos.rt[ridx].prefix < 0) {
    printf("FlowOS: prefix length should be between 0 - 32.\n");
    exit(4);
  }
  
  flowos.rt[ridx].mask = mask_from_prefix(flowos.rt[ridx].prefix);
  flowos.rt[ridx].masked = flowos.rt[ridx].daddr & flowos.rt[ridx].mask;
  flowos.rt[ridx].nif = ifidx;
}

/*------------------------------------------------*/
static int config_routing_table_from_file(char *file)  {
#define ROUTES "ROUTES"
  int i;  
  FILE *fc;
  char optstr[MAX_OPTLINE_LEN];
  
  printf("FlowOS: loading routing configurations from : %s\n", file);  
  fc = fopen(file, "r");
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
      if (num <= 0)	break;
      
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
  uint8_t *dip;
  uint8_t *mask;
  uint8_t *md;
  
  /* print out process start information */
  printf("FlowOS: Routes\n");
  for (i = 0; i < flowos.routes; i++) {
    dip = (uint8_t *)&flowos.rt[i].daddr;
    mask = (uint8_t *)&flowos.rt[i].mask;
    md = (uint8_t *)&flowos.rt[i].masked;
    printf("Destination: %u.%u.%u.%u/%d, Mask: %u.%u.%u.%u, "
					 "Masked: %u.%u.%u.%u, Route: eth%d\n", 
					 dip[0], dip[1], dip[2], dip[3], 
					 flowos.rt[i].prefix, 
					 mask[0], mask[1], mask[2], mask[3], 
					 md[0], md[1], md[2], md[3], 
					 flowos.rt[i].nif);
  }
  if (flowos.routes == 0)
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
int flowos_config_routing_table(char *file) {
  int i, ridx;
  unsigned int c;
  
  flowos.routes = 0;
  
  flowos.rt = (struct route_table *)
    rte_calloc("route_table", MAX_DEVICES, sizeof(struct route_table), 0);
  if (! flowos.rt) {
    rte_exit(EXIT_FAILURE, "FlowOS: failed to allocate routing table.");
  }
  /* set default routing table */
	printf("FlowOS: configuring default routes\n");
  for (i = 0; i < flowos.device_count; i++) {
		if (flowos.devices[i].configured) {
			ridx = flowos.routes++;
			flowos.rt[ridx].daddr = flowos.devices[i].ip_addr & flowos.devices[i].netmask;
			
			flowos.rt[ridx].prefix = 0;
			c = flowos.devices[i].netmask;
			while ((c = (c >> 1))){
				flowos.rt[ridx].prefix++;
			}
			flowos.rt[ridx].prefix++;
    
			flowos.rt[ridx].mask = flowos.devices[i].netmask;
			flowos.rt[ridx].masked = flowos.rt[ridx].daddr;
			flowos.rt[ridx].nif = i; //flowos.devices[i].ifindex;
		}
  }
  /* set additional routing table */
	printf("FlowOS: configuring routes from file: %s\n", file);
  config_routing_table_from_file(file);

	flowos_print_routing_table();

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
  for (i = 0; i < flowos.device_count; i++) {    
		uint8_t *mac = (uint8_t *) flowos.devices[i].mac_addr;
    uint8_t *ip = (uint8_t *)&flowos.devices[i].ip_addr;
    uint8_t *mask = (uint8_t *)&flowos.devices[i].netmask;
    
    printf("Interface: %s, "
					 "MAC: %02X:%02X:%02X:%02X:%02X:%02X, "
					 "IP: %u.%u.%u.%u, "
					 "NetMask: %u.%u.%u.%u\n",
					 flowos.devices[i].name, 
					 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
					 ip[0], ip[1], ip[2], ip[3],
					 mask[0], mask[1], mask[2], mask[3]);
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
  
  idx = flowos.arp.entries++;
  flowos.arp.entry[idx].prefix = prefix;
  parse_ip_address(&flowos.arp.entry[idx].ip, dip_s);
  parse_mac_address(flowos.arp.entry[idx].haddr, daddr_s);
  
  dip_mask = mask_from_prefix(prefix);
  flowos.arp.entry[idx].ip_mask = dip_mask;
  flowos.arp.entry[idx].ip_masked = flowos.arp.entry[idx].ip & dip_mask;
  
/*
  int i, cnt;
  cnt = 1;
  cnt = cnt << (32 - prefix);
  
  for (i = 0; i < cnt; i++) {
  idx = flowos.arp.entries++;
  flowos.arp.entry[idx].ip = htonl(ntohl(ip) + i);
  memcpy(flowos.arp.entry[idx].haddr, haddr, ETH_ALEN);
  }
*/
}

/*---------------------------------------------------------*/
int flowos_config_arp_table(char *file) {
#define ARP_ENTRY "ARP_ENTRY"
  FILE *fc;
  char optstr[MAX_OPTLINE_LEN];
  int numEntry = 0;
  int hasNumEntry = 0;
  
  printf("FlowOS: loading ARP table from : %s\n", file);  
  fc = fopen(file, "r");
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
      flowos.arp.entry = (struct arp_entry *)
				rte_calloc("arp_entry", numEntry + MAX_ARPENTRY, sizeof(struct arp_entry), 0);
      if (flowos.arp.entry == NULL) {
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

static int get_next_line(FILE *file, char *line) {
	char *ptr;
	char *temp;    	
	while (1) {
    if (fgets(line, MAX_OPTLINE_LEN, file) == NULL)
      return 0;
    ptr = line;
    // skip comment
    if ((temp = strchr(ptr, '#')) != NULL) *temp = 0;
    // remove front white spaces
    while (*ptr && isspace((int)*ptr)) ptr++;
		// remove tailing white spaces
    temp = ptr + strlen(ptr) - 1;
    while (temp >= ptr && isspace((int)*temp)) {
			*temp = '\0';
			temp--;
		}
    if (*ptr == '\0') continue;
		else break;
	}
	memcpy(line, ptr, strlen(ptr));
	line[strlen(ptr)] = '\0';
	return strlen(ptr);
}

/*-------------------------------------------------------------*/
int flowos_config_interfaces(char *file) {
  FILE *fc;
  char line[MAX_OPTLINE_LEN];
	char *p1, *q1, *p2, *q2, *p3, *q3;
	
  int ret, idx, numEntry = 0;
  
  printf("FlowOS: loading interface config: %s\n", file);  
  fc = fopen(file, "r");
  if (fc == NULL) {
    perror("fopen");
    printf("FlowOS: skips loading static interface configuration\n");
    return -1;
  }
	while (get_next_line(fc, line) > 0) {
		/* Parse interface configuration */
		p1 = strtok(line, " \t=");
		q1 = strtok(NULL, " \t=");
		p2 = strtok(NULL, " \t=");
		q2 = strtok(NULL, " \t=");
		p3 = strtok(NULL, " \t=");
		q3 = strtok(NULL, " \t=");
		assert(p1 && q1 && p2 && q2 && p3 && q3);
		/* Parse interface index */
		idx = atoi(q1); 
		if (strcmp(p1, "ifconfig") != 0 || 
				idx < 0 || idx >= flowos.device_count) {
			printf("FlowOS: invalind configuration option, %s %s, expects ifconfig index\n", p1, q1);
			fclose(fc);
			return numEntry;
		}
		/* Parse interface IP address */
		ret = parse_ip_address(&flowos.devices[idx].ip_addr, q2);
		if (strcmp(p2, "address") != 0 || ret < 0) {
			printf("FlowOS: invalid ifconfig option %s %s, expects address IP\n", p2, q2);
			fclose(fc);
			return numEntry;
		}
		/* Parse interface netmask */
		ret = parse_ip_address(&flowos.devices[idx].netmask, q3);
    if (strcmp(p3, "netmask") != 0 || ret < 0) {      
			printf("FlowOS: invalid ifconfig option %s %s, expects netmask mask\n", p3, q3);
			fclose(fc);
			return numEntry;
		}
		flowos.devices[idx].configured = 1; 
		numEntry++;
  }
  fclose(fc);
	return numEntry;
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
  else if (strcmp(p, "num_cores") == 0) {
    flowos.tcp.num_cpus = atoi(q);
    if (flowos.tcp.num_cpus <= 0) {
      printf("FlowOS: number of CPU cores should be larger than 0.\n");
      return -1;
    }
    if (flowos.tcp.num_cpus > flowos.cpu_count) {
      printf("FlowOS: number of cores should be smaller than "
		   "# physical CPU cores.\n");
      return -1;
    }
  }
  else if (strcmp(p, "max_concurrency") == 0) {
		flowos.tcp.max_concurrency = atoi(q);
    if (flowos.tcp.max_concurrency < 0) {
      printf("FlowOS: the maximum concurrency should be larger than 0.\n");
      return -1;
    }
  } 
  else if (strcmp(p, "max_num_buffers") == 0) {
    flowos.tcp.max_num_buffers = atoi(q);
    if (flowos.tcp.max_num_buffers < 0) {
      printf("FlowOS: the maximum # buffers should be larger than 0.\n");
      return -1;
    }
  } 
  else if (strcmp(p, "rcvbuf") == 0) {
    flowos.tcp.rcvbuf_size = atoi(q);
    if (flowos.tcp.rcvbuf_size < 64) {
      printf("FlowOS: receive buffer size should be larger than 64.\n");
      return -1;
    }
  } 
  else if (strcmp(p, "sndbuf") == 0) {
    flowos.tcp.sndbuf_size = atoi(q);
    if (flowos.tcp.sndbuf_size < 64) {
      printf("FlowOS: send buffer size should be larger than 64.\n");
      return -1;
    }
  } 
  else if (strcmp(p, "tcp_timeout") == 0) {
    flowos.tcp.tcp_timeout = atoi(q);
    if (flowos.tcp.tcp_timeout > 0) {
      flowos.tcp.tcp_timeout = SEC_TO_USEC(flowos.tcp.tcp_timeout) / TIME_TICK;
    }
  } 
  else if (strcmp(p, "tcp_timewait") == 0) {
    flowos.tcp.tcp_timewait = atoi(q);
    if (flowos.tcp.tcp_timewait > 0) {
      flowos.tcp.tcp_timewait = SEC_TO_USEC(flowos.tcp.tcp_timewait) / TIME_TICK;
    }
  } 
  /* else if (strcmp(p, "stat_print") == 0) { */
  /*   int i; */
    
  /*   for (i = 0; i < flowos.device_count; i++) { */
  /*     if (strcmp(flowos.devices[i].name, q) == 0) { */
	/* 			flowos.devices[i].stat_print = 1; // TRUE */
  /*     } */
  /*   } */
  /* }  */
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
  flowos.tcp.num_cpus = 1; // flowos.cpu_count;
  flowos.tcp.max_concurrency = 100000;
  flowos.tcp.max_num_buffers = 100000;
  flowos.tcp.rcvbuf_size = 8192;
  flowos.tcp.sndbuf_size = 8192;
  flowos.tcp.tcp_timeout = TCP_TIMEOUT;
  flowos.tcp.tcp_timewait = TCP_TIMEWAIT;
  
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
  printf("Number of CPU cores to use: %d\n", flowos.tcp.num_cpus);
  printf("Maximum number of concurrency per core: %d\n", 
	       flowos.tcp.max_concurrency);
  
  printf("Maximum number of preallocated buffers per core: %d\n", 
	       flowos.tcp.max_num_buffers);
  printf("Receive buffer size: %d\n", flowos.tcp.rcvbuf_size);
  printf("Send buffer size: %d\n", flowos.tcp.sndbuf_size);
	
  if (flowos.tcp.tcp_timeout > 0) {
    printf("TCP timeout seconds: %d\n", 
		 USEC_TO_SEC(flowos.tcp.tcp_timeout * TIME_TICK));
  } 
  else {
    printf("TCP timeout check disabled.\n");
  }
  printf("TCP timewait seconds: %d\n", 
	       USEC_TO_SEC(flowos.tcp.tcp_timewait * TIME_TICK));

  /* printf("NICs to print statistics:"); */
  /* for (i = 0; i < flowos.devices_count; i++) { */
  /*   if (flowos.devices[i].stat_print) { */
  /*     printf(" %s", flowos.devices[i].dev_name); */
  /*   } */
  /* } */
  printf("\n");
  printf("----------------------------------------------------------"
				 "-----------------------\n");
}
/*--------------------------------------------------------------*/
