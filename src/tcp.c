#ifndef __TCP_C__
#define __TCP_C__

#include <type.h>
#include <transport.h>
#include <common.h>

#include <tcp.h>

/********************************************************************
 *Extern Declaration
 *
 ********************************************************************/
extern int32_t tun_write(uint8_t *packet_ptr, uint16_t packet_length);

extern int32_t nat_perform_snat(uint8_t  *packet_ptr, 
                                uint16_t packet_length, 
                                uint8_t  *snat_ptr, 
                                uint16_t *snat_length);

extern uint16_t utility_cksum(void *pkt_ptr, size_t pkt_len);

/********************************************************************
 *Global Definition
 *
 ********************************************************************/
tcp_ctx_t tcp_ctx_g;

/********************************************************************
 *Function Definitions
 *
 ********************************************************************/
int32_t tcp_init(uint32_t ip_addr, 
                 uint32_t ip_mask,
                 uint32_t uam_ip,
                 uint16_t uam_port,
                 uint32_t radius_ip,
                 uint16_t radius_port) {

  tcp_ctx_t *pTcpCtx = &tcp_ctx_g;

  pTcpCtx->ip_addr     = ip_addr;
  pTcpCtx->ip_mask     = ip_mask;
  pTcpCtx->uam_ip      = uam_ip;
  pTcpCtx->uam_port    = uam_port;
  pTcpCtx->radius_ip   = radius_ip;
  pTcpCtx->radius_port = radius_port;
 
  return(0); 
}/*tcp_init*/

uint16_t tcp_checksum(uint8_t *packet_ptr) {
  uint8_t *tcp_pseudo_header = NULL;
  uint16_t tmp_len = 0;
  uint16_t offset = 0;
  uint16_t ip_header_len = 0;
  uint16_t checksum = 0;
  struct iphdr *iphdr_ptr = (struct iphdr *)packet_ptr;

  ip_header_len = (iphdr_ptr->ip_len * 4);

  /*TCP pseudo header*/
  tmp_len = (ntohs(iphdr_ptr->ip_tot_len) - ip_header_len) + 12/*pseudo header length*/;

  tcp_pseudo_header = (uint8_t *)malloc(tmp_len);

  if(NULL == tcp_pseudo_header) {
    fprintf(stderr, "\n%s:%d memory allocation failed\n", 
                    __FILE__, 
                    __LINE__);
    exit(0);
  }
  memset((void *)tcp_pseudo_header, 0, tmp_len);
        
  /*Source IP*/
  *((uint32_t *)&tcp_pseudo_header[offset]) = iphdr_ptr->ip_src_ip;
  offset += 4;
  /*Destination IP*/
  *((uint32_t *)&tcp_pseudo_header[offset]) = iphdr_ptr->ip_dest_ip;
  offset += 4;
  /*Reserved*/
  tcp_pseudo_header[offset] = 0;
  offset += 1;
  /*Protocol from ip header*/
  tcp_pseudo_header[offset] = iphdr_ptr->ip_proto;
  offset += 1;

  /*TCP Length*/
  *((uint16_t *)&tcp_pseudo_header[offset]) = 
               htons(ntohs(iphdr_ptr->ip_tot_len) - ip_header_len);
  offset += 2;

  /*copy the header + payload*/
  memcpy((void *)&tcp_pseudo_header[offset], 
         (const void *)&packet_ptr[ip_header_len], 
         (ntohs(iphdr_ptr->ip_tot_len) - ip_header_len));

  offset += ntohs(iphdr_ptr->ip_tot_len) - ip_header_len;

  checksum = utility_cksum((void *)tcp_pseudo_header, offset);

  /*freeing the allocated one*/
  free(tcp_pseudo_header);
  tcp_pseudo_header = NULL;

  return(checksum);
}/*tcp_checksum*/


int32_t tcp_main(uint16_t fd, 
                 uint8_t *packet_ptr, 
                 uint16_t packet_length) {

  struct iphdr *iphdr_ptr;
  struct tcp *tcphdr_ptr;
  tcp_ctx_t *pTcpCtx = &tcp_ctx_g;
  uint8_t  buffer[1500];
  uint16_t buffer_len = 0;
  int32_t  ret = -1;

  iphdr_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)];
  tcphdr_ptr = (struct tcp *)&packet_ptr[sizeof(struct eth) + sizeof(struct iphdr)];

  /*Whose request is for?*/
  if((ntohl(iphdr_ptr->ip_dest_ip) & ntohl(pTcpCtx->ip_mask)) != 
     (ntohl(pTcpCtx->ip_addr) & ntohl(pTcpCtx->ip_mask))) {

    /*Request is for other*/
    nat_perform_snat(packet_ptr, 
                     packet_length, 
                     (uint8_t *)buffer, 
                     &buffer_len);

    ret = tun_write(buffer, buffer_len);

    if(ret < 0) {
      perror("\nwriting to tun failed\n");
      return(-1);
    }
  }
  return(0);

}/*tcp_main*/


#endif /* __TCP_C__ */
