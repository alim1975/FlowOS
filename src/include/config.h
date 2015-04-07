#ifndef __CONFIG__
#define __CONFIG__

int flowos_config_interfaces(char *file);

void flowos_print_interface_info();

int flowos_config_arp_table(char *file);

int flowos_config_routing_table(char *file);

void flowos_print_routing_table();

int flowos_config_tcp(char *file);

void flowos_print_tcp_config();

int set_socket_mode(int8_t socket_mode);

#endif /* __CONFIG__ */
