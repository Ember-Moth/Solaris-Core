#ifndef SOLARIS_LWIP_OPTIONS_H
#define SOLARIS_LWIP_OPTIONS_H
#include "solaris_lwip_symbols.h"
#include "solaris_lwip_def.h"
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#include <stddef.h>
void *solaris_lwip_allocate(size_t size);
void *solaris_lwip_callocate(size_t count, size_t size);
void solaris_lwip_deallocate(void *pointer);
#define sys_now solaris_lwip_now
#define tcp_timer_needed solaris_lwip_timer_needed
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_TIMERS 0
#define LWIP_TCP 1
#define LWIP_UDP 0
#define LWIP_UDPLITE 0
#define LWIP_RAW 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_ICMP 1
#define LWIP_ICMP6 1
#define LWIP_DHCP 0
#define LWIP_DNS 0
#define LWIP_AUTOIP 0
#define LWIP_IGMP 0
#define LWIP_IPV6_MLD 0
#define LWIP_IPV6_AUTOCONFIG 0
#define LWIP_IPV6_DHCP6 0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS 0
#define IP_REASSEMBLY 0
#define IP_FRAG 0
#define LWIP_IPV6_REASS 0
#define LWIP_IPV6_FRAG 0
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_HAVE_LOOPIF 0
#define LWIP_SINGLE_NETIF 1
#define LWIP_STATS 0
#define MEM_CUSTOM_ALLOCATOR 1
#define MEM_CUSTOM_MALLOC solaris_lwip_allocate
#define MEM_CUSTOM_CALLOC solaris_lwip_callocate
#define MEM_CUSTOM_FREE solaris_lwip_deallocate
#define MEMP_MEM_MALLOC 1
#define MEM_ALIGNMENT 8
#define TCP_MSS 1440
#define TCP_WND 32768
#define TCP_SND_BUF 32768
#define TCP_SND_QUEUELEN 128
#define TCP_QUEUE_OOSEQ 1
#define TCP_OOSEQ_MAX_BYTES 32768
#define TCP_OOSEQ_MAX_PBUFS 64
#define TCP_LISTEN_BACKLOG 1
#define LWIP_TCP_TIMESTAMPS 1
#define LWIP_TCP_SACK_OUT 1
#define LWIP_CHECKSUM_CTRL_PER_NETIF 0
#endif
