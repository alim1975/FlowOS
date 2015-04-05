#ifndef __CONFIG_H__
#define __CONFIG_H__

int flowos_load_tcp_config(char *fname);

/* set configurations from the setted 
   interface information */
int flowos_set_device_info();

/* set configurations from the files */
int flowos_config_routing_table();

int flowos_config_arp_table();

/* print setted configuration */
void flowos_print_tcp_config();

void flowos_print_interface_config();

void flowos_print_routing_table();

/* set socket modes */
int set_socket_mode(int8_t socket_mode);

#endif /* __CONFIG_H__ */
