#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uv.h>
#include "aproxy/direct_outbound.h"
#include "aproxy/packet_session.h"
#include "aproxy/packet_udp_relay.h"

static aproxy_packet_udp_relay_t *relay;
static int ipv6_status;
static unsigned replies, empty_replies, alternate_replies;
static unsigned alternate_port, observed_alternate_port;
static unsigned packet_errors;

static void put16(unsigned char *p, unsigned v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static unsigned get16(const unsigned char *p) { return ((unsigned)p[0]<<8)|p[1]; }
static void opened(aproxy_packet_session_t *session, aproxy_stream_t *stream,
                   const aproxy_packet_flow_key_t *key, void *ctx) {
    (void)ctx;
    int rc=aproxy_packet_udp_relay_on_session(relay,session,stream,key);
    if(key->family==APROXY_PACKET_FAMILY_IPV6) ipv6_status=rc;
    if(rc!=0) { aproxy_stream_close(stream); aproxy_stream_free(stream); }
}
static void received(aproxy_packet_session_t *session, aproxy_stream_t *stream,
                     const uint8_t *data, size_t len, void *ctx) {
    (void)ctx;
    if(aproxy_packet_udp_relay_on_packet(relay,session,stream,data,len)!=0) packet_errors++;
}
static int writeback(aproxy_packet_session_t *session, const uint8_t *p,
                     size_t len, void *ctx) {
    (void)session; (void)ctx;
    if(len<28) return -1;
    replies++;
    if(get16(p+24)==8) empty_replies++;
    if(len==31 && memcmp(p+28,"ALT",3)==0) {
        alternate_replies++; observed_alternate_port=get16(p+20);
    }
    return 0;
}
static int echo_socket(unsigned *port) {
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if(fd<0) return -1;
    struct sockaddr_in addr={0}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(fd,(struct sockaddr*)&addr,sizeof(addr))!=0) { close(fd); return -1; }
    socklen_t n=sizeof(addr);
    if(getsockname(fd,(struct sockaddr*)&addr,&n)!=0 || fcntl(fd,F_SETFL,O_NONBLOCK)<0) { close(fd); return -1; }
    *port=ntohs(addr.sin_port); return fd;
}
static int inject4(aproxy_packet_session_table_t *table,unsigned port,unsigned char value) {
    unsigned char p[29]={0}; p[0]=0x45; put16(p+2,sizeof(p)); p[8]=64; p[9]=17;
    inet_pton(AF_INET,"10.8.0.2",p+12); inet_pton(AF_INET,"127.0.0.1",p+16);
    put16(p+20,40000); put16(p+22,port); put16(p+24,9); p[28]=value;
    unsigned sum=0; for(unsigned i=0;i<20;i+=2) sum+=get16(p+i);
    while(sum>>16) sum=(sum&65535)+(sum>>16); put16(p+10,(~sum)&65535);
    return aproxy_packet_session_table_dispatch_packet(table,p,sizeof(p));
}
int main(void) {
    uv_loop_t loop; if(uv_loop_init(&loop)!=0) return 1;
    aproxy_outbound_t *outbound=NULL;
    aproxy_direct_outbound_config_t direct={.loop=&loop,.tag="direct"};
    aproxy_router_t *router=NULL; aproxy_packet_session_table_t *table=NULL;
    if(aproxy_direct_outbound_new(&direct,&outbound)!=0 || aproxy_router_new(&router)!=0 ||
       aproxy_router_set_default(router,outbound)!=0) return 2;
    aproxy_packet_udp_relay_config_t rcfg={.router=router};
    aproxy_packet_session_table_config_t tcfg={.on_open=opened,.on_data=received,.on_write=writeback};
    if(aproxy_packet_udp_relay_new(&rcfg,&relay)!=0 || aproxy_packet_session_table_new(&tcfg,&table)!=0) return 3;
    unsigned pa,pb; int servers[2]={echo_socket(&pa),echo_socket(&pb)};
    int alt=echo_socket(&alternate_port);
    if(servers[0]<0 || servers[1]<0 || alt<0) return 4;
    if(inject4(table,pa,'A')!=0 || inject4(table,pb,'B')!=0 || inject4(table,pa,'a')!=0) return 5;
    unsigned seen[2]={0}, origins[2]={0}; int same_a=1, sent_extra=0;
    uint64_t start=uv_hrtime();
    while(uv_hrtime()-start<UINT64_C(500000000)) {
        uv_run(&loop,UV_RUN_NOWAIT);
        for(unsigned i=0;i<2;i++) for(;;) {
            char b[128]; struct sockaddr_in from; socklen_t n=sizeof(from);
            ssize_t got=recvfrom(servers[i],b,sizeof(b),0,(struct sockaddr*)&from,&n);
            if(got<0) break;
            unsigned port=ntohs(from.sin_port);
            if(seen[i] && origins[i]!=port && i==0) same_a=0;
            origins[i]=port; seen[i]++;
            if(sendto(servers[i],b,(size_t)got,0,(struct sockaddr*)&from,n)!=got) return 6;
            if(i==0 && !sent_extra) {
                if(sendto(servers[i],"",0,0,(struct sockaddr*)&from,n)!=0 ||
                   sendto(alt,"ALT",3,0,(struct sockaddr*)&from,n)!=3) return 7;
                sent_extra=1;
            }
        }
        uv_sleep(1);
    }
    unsigned char v6[49]={0}; v6[0]=0x60; put16(v6+4,9); v6[6]=17; v6[7]=64;
    inet_pton(AF_INET6,"fd00:7357:1::2",v6+8); inet_pton(AF_INET6,"::1",v6+24);
    put16(v6+40,40000); put16(v6+42,pb); put16(v6+44,9); v6[48]='6';
    unsigned checksum6=9+17;
    for(unsigned i=8;i<48;i+=2) checksum6+=get16(v6+i);
    checksum6+=(unsigned)v6[48]<<8;
    while(checksum6>>16) checksum6=(checksum6&65535)+(checksum6>>16);
    unsigned wire_checksum=(~checksum6)&65535; put16(v6+46,wire_checksum ? wire_checksum : 65535);
    int dispatch6=aproxy_packet_session_table_dispatch_packet(table,v6,sizeof(v6));
    aproxy_packet_udp_relay_stats_t stats; aproxy_packet_udp_relay_get_stats(relay,&stats);
    printf("{\"peer_packets\":[%u,%u],\"egress_source_ports\":[%u,%u],\"same_destination_reuses_port\":%s,\"cross_destination_reuses_port\":%s,\"relay_sessions\":%llu,\"reply_packets\":%u,\"empty_replies\":%u,\"alternate_source_preserved\":%s,\"ipv6_open_status\":%d,\"ipv6_dispatch_status\":%d,\"packet_errors\":%u}\n",
      seen[0],seen[1],origins[0],origins[1],same_a?"true":"false",origins[0]==origins[1]?"true":"false",
      (unsigned long long)stats.sessions_opened,replies,empty_replies,
      alternate_replies==1 && alternate_port==observed_alternate_port?"true":"false",ipv6_status,dispatch6,packet_errors);
    close(servers[0]); close(servers[1]); close(alt);
    aproxy_packet_udp_relay_free(relay); relay=NULL;
    aproxy_packet_session_table_free(table); aproxy_router_free(router); aproxy_outbound_free(outbound);
    uv_run(&loop,UV_RUN_DEFAULT); int cleanup=uv_loop_close(&loop);
    return seen[0]==2 && seen[1]==1 && packet_errors==0 && cleanup==0 ? 0 : 8;
}
