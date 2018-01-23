#ifndef __DNS_C__
#define __DNS_C__

#include <dns.h>
#include <transport.h>

/*Global Variable*/
dns_ctx_t dns_ctx_g;

/*********************************************************************
 * Extern Declaration
 ********************************************************************/
extern uint32_t  utility_ip_str_to_int(uint8_t *record);

extern int32_t   db_exec_query(char *sql_query);

extern int32_t   db_process_query_result(int32_t *row_count, 
                                         int32_t *column_count, 
                                         char ***result);

extern uint16_t  utility_cksum(void *pkt_ptr, size_t pkt_len);

extern int32_t   write_eth_frame (int32_t fd,
                                  uint8_t *dst_mac,
                                  uint8_t *packet, 
                                  uint32_t packet_len);

extern timer_t   timer_create_timer(uint32_t (*callback_handler)(void *));

extern uint32_t timer_set_timer(uint32_t sec, 
                                uint32_t nano_sec, 
                                void *ctx_data, 
                                timer_t tid);

extern int32_t tun_write(uint8_t *packet_ptr, uint16_t packet_length);

extern int32_t nat_perform_dnat(uint8_t *packet_ptr, 
                                uint16_t packet_length,
                                uint8_t *dnat_ptr,
                                uint16_t *dnat_length);

extern int32_t nat_perform_snat(uint8_t *packet_ptr, 
                                uint16_t packet_length, 
                                uint8_t *snat_ptr, 
                                uint16_t *snat_length);

/********************************************************************
 * Function Definition
 ********************************************************************/
uint32_t dns_snat_request_timeout_callback(void *ctx_data) {

  /*SEND ICMP Response as Destination Not Rchable*/  
  fprintf(stderr, "Timeout for SNAT Request\n");

  return(0);
}/*dns_snat_request_timeout_callback*/


uint32_t dns_init(uint8_t *table_name,
                  uint8_t *ip_allocation_table) {


  uint8_t sql_query[256];
  int32_t row;
  int32_t col;
  char record[2][16][32];

  dns_ctx_t *pDnsCtx = &dns_ctx_g;

  memset((void *)&sql_query, 0, sizeof(sql_query));
  /*check if DNS query is for local DNS or external one.*/
  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s",
           "SELECT * from ",
           table_name);
     
  if(!db_exec_query((char *)sql_query)) {
    
    memset((void *)record, 0, (2 * 16 * 32));
    if(!db_process_query_result(&row, &col, (char ***)record)) {

      if(row) {

        /*DNS1 IP*/ 
        memset((void *)pDnsCtx->dns1, 0, sizeof(pDnsCtx->dns1));
        memcpy((void *)pDnsCtx->dns1, 
               (const void *)record[0][1], 
               strlen((const char *)record[0][1]));

        /*DNS2 IP*/
        memset((void *)pDnsCtx->dns2, 0, sizeof(pDnsCtx->dns2));
        memcpy((void *)pDnsCtx->dns2, 
               (const void *)record[0][2], 
               strlen((const char *)record[0][2]));

        /*Get the NS - Name Server IP Address, the 8th column*/
        memset((void *)pDnsCtx->ns1_ip, 0, sizeof(pDnsCtx->ns1_ip));
        memcpy((void *)pDnsCtx->ns1_ip, 
               (const void *)record[0][3], 
               strlen((const char *)record[0][3]));

        memset((void *)pDnsCtx->ns1_name, 0, sizeof(pDnsCtx->ns1_name));
        gethostname(pDnsCtx->ns1_name, sizeof(pDnsCtx->ns1_name));

        memset((void *)pDnsCtx->domain_name, 0, sizeof(pDnsCtx->domain_name));
        memcpy((void *)pDnsCtx->domain_name, 
               (const void *)record[0][0], 
               strlen((const char *)record[0][0]));
      }
    } 
  }

  memcpy((void *)pDnsCtx->ip_allocation_table, 
         (const void *)ip_allocation_table, 
         strlen((const char *)ip_allocation_table));
  /*Create the Timer*/
  pDnsCtx->snat_tid = timer_create_timer(dns_snat_request_timeout_callback);

  return(0);
}/*dns_init*/


uint32_t dns_is_dns_query(int16_t fd, 
                          uint8_t *packet_ptr, 
                          uint16_t packet_length) {

  struct dnshdr *dns_packet = (struct dnshdr *)&packet_ptr[sizeof(struct eth)   +
                                                           sizeof(struct iphdr) +
                                                           sizeof(struct udphdr)];
  return(!dns_packet->ra && !dns_packet->opcode);
  
}/*dns_is_dns_query*/

uint32_t dns_get_label(uint8_t *domain_name, uint8_t **label_str) {
  uint32_t idx = 0;

  sscanf((const char *)domain_name, "%s.%s", label_str[0], label_str[1]);
  (void)idx;

  return(0);
}/*dns_get_label*/

uint16_t dns_update_cache(uint8_t *packet_ptr) {
  uint8_t sql_query[255];
  int16_t dns_uid = 0x00;
  uint8_t src_ip_str[32];
  uint8_t src_mac_str[32];
  uint8_t protocol_str[8];

  struct eth    *eth_ptr     = (struct eth *)packet_ptr;
  struct iphdr  *iphdr_ptr   = (struct iphdr  *)&packet_ptr[sizeof(struct eth)];
  struct udphdr *udphdr_ptr  = (struct udphdr *)&packet_ptr[sizeof(struct eth) + sizeof(struct iphdr)];

  /*source port must be greater than 1024. below to this is reserved for standard protocol.*/ 
  dns_uid = ((random() + 1024) % ~(1 << sizeof(uint16_t))); 
  
  memset((void *)&src_ip_str, 0, sizeof(src_ip_str));
  utility_ip_int_to_str(iphdr_ptr->ip_src_ip, src_ip_str);

  memset((void *)&src_mac_str, 0, sizeof(src_mac_str));
  utility_mac_int_to_str(eth_ptr->h_source,  src_mac_str);

  memset((void *)&protocol_str, 0, sizeof(protocol_str));
  utility_protocol_int_to_str(iphdr_ptr->ip_proto, protocol_str);

  memset((void *)&sql_query, 0, sizeof(sql_query));
  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s%s%s%s%s"
           "%s%s%s%d%s%d%s%d%s",
           "INSERT INTO dns_nat_table (xid, src_ip, src_mac, "
           "protocol, dns_uid, src_port, dest_ip, dest_port) VALUES (",
           "NULL",
           ",'",
           src_ip_str,
           "',",
           "'",
           src_mac_str,
           "',",
           "'",
           protocol_str,
           "',",
           "'",
           dns_uid,
           "',",
           ntohs(udphdr_ptr->udp_src_port),
           ",NULL,",
           12,
           ")");

  if(db_exec_query((char *)sql_query)) {
    /*SQL failed in syntax*/
    fprintf(stderr, "\nSQL QUERY failed %s\n", sql_query);
    exit(0);
  }
  
  return(dns_uid);
}/*dns_update_cache*/

uint32_t dns_dnat_get_ip_and_mac(uint8_t  *packet_ptr, 
                                 uint32_t src_ip, 
                                 uint32_t *dest_ip, 
                                 uint8_t  *dest_mac,
                                 uint16_t *dest_port) {
  uint8_t sql_query[256];
  uint8_t src_ip_str[32];

  int32_t row = 0;
  int32_t col = 0;
  char  record[2][16][32];
  uint16_t src_port = 0;

  src_port = ((struct udphdr *)&packet_ptr[sizeof(struct eth) + 
              sizeof(struct iphdr)])->udp_dest_port;
  memset((void*)src_ip_str, 0, sizeof(src_ip_str));

  utility_ip_int_to_str(src_ip, src_ip_str);

  memset((void *)&sql_query, 0, sizeof(sql_query));
  snprintf((char *)sql_query,
           sizeof(sql_query),
           "%s%s%s%s%d%s",
           "SELECT * FROM dns_nat_table WHERE (dest_ip ='",
           src_ip_str,
           "'",
           "AND src_port=",
            src_port,
           ")");

  if(!db_exec_query((char *)sql_query)) {
   
    memset((void *)record, 0, (sizeof(int8_t) * 2 * 16 * 32));
    if(!db_process_query_result(&row, &col, (char ***)record)) {

      if(row) {
        *dest_ip = utility_ip_str_to_int(record[0][1]);
         utility_mac_str_to_int(record[0][2], dest_mac);
        *dest_port = utility_ip_str_to_int(record[0][5]);
      }
    } 
  }

  return(0);
}/*dns_dnat_get_ip_and_mac*/


uint32_t dns_get_mac_from_ARP_cache(uint32_t ip, uint8_t *dst_mac) {
  uint8_t ip_str[32];
  uint8_t sql_query[256];

  int32_t row;
  int32_t col;
  char  record[2][16][32];

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(ip, ip_str);
  
  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s",
           "SELECT * FROM arp_cache_table where ip ='",
           ip_str,
           "'");

  if(!db_exec_query((char *)sql_query)) {

    memset((void *)record, 0, (sizeof(uint8_t) * 2 * 16 * 32));
    if(!db_process_query_result(&row, &col, (char ***)record)) {

      if(row) {
        utility_mac_str_to_int((char *)record[0][1], (uint8_t *)dst_mac);
      } else {
        uint8_t bmac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        memcpy((void *)&dst_mac, (void *)bmac, 6);
      }
    } 
  }
  
  return(0);
}/*dns_get_mac_from_ARP_cache*/

uint32_t dns_perform_snat(int16_t fd, 
                          uint8_t *packet_ptr, 
                          uint16_t packet_length) {

  int32_t ret = -1;
  uint8_t buffer[1500];
  uint16_t buffer_length;
 
  memset((void *)buffer, 0, sizeof(buffer)) ;

  ret = nat_perform_snat(packet_ptr, 
                         packet_length, 
                         (uint8_t *)buffer, 
                         &buffer_length); 
  
  ret = tun_write(buffer, 
                  buffer_length);
  if(ret < 0) {
    fprintf(stderr, "\nwrite to tunnel failed\n");
    perror("tun:");
  }
  return (0);
  
}/*dns_perform_snat*/

uint32_t dns_perform_dnat(int16_t fd, 
                          uint8_t *packet_ptr, 
                          uint16_t packet_length) {
  uint8_t buffer[1500];
  uint16_t buffer_len = 0x00;
  uint8_t  dst_mac[6];

  memset((void *)buffer, 0, sizeof(buffer));

  nat_perform_dnat(packet_ptr, 
                   packet_length, 
                   buffer, 
                   &buffer_len);
  
  memset((void *)dst_mac, 0, sizeof(dst_mac));
  memcpy((void *)dst_mac, (const void *)buffer, 6);

  write_eth_frame(fd, dst_mac, buffer, buffer_len);
  return(0);

}/*dns_perform_dnat*/

uint32_t dns_build_rr_reply(int16_t fd, 
                            uint8_t *packet_ptr, 
                            uint16_t packet_length) {
  uint8_t rr_reply[1500];

  uint8_t  *rsp_ptr    = rr_reply;
  uint32_t  offset     = 0;
  uint8_t  *pseudo_ptr = NULL;
  uint32_t  idx        = 0;
  uint8_t   label_str[2][255];
  
  dns_ctx_t *pDnsCtx   = &dns_ctx_g;
 
  struct eth    *eth_ptr  = (struct eth    *)packet_ptr;
  struct iphdr  *ip_ptr   = (struct iphdr  *)&packet_ptr[sizeof(struct eth)];
  struct udphdr *udp_ptr  = (struct udphdr *)&packet_ptr[sizeof(struct eth) + 
                                                         sizeof(struct iphdr)];

  struct dnshdr *dns_ptr  = (struct dnshdr *)&packet_ptr[sizeof(struct eth) + 
                                                         sizeof(struct iphdr) + 
                                                         sizeof(struct udphdr)];
 
  struct eth    *eth_rsp_ptr  = (struct eth    *)rsp_ptr;
  struct iphdr  *ip_rsp_ptr   = (struct iphdr  *)&rsp_ptr[sizeof(struct eth)];
  struct udphdr *udp_rsp_ptr  = (struct udphdr *)&rsp_ptr[sizeof(struct eth) + 
                                                          sizeof(struct iphdr)];

  struct dnshdr *dns_rsp_ptr  = (struct dnshdr *)&rsp_ptr[sizeof(struct eth) + 
                                                          sizeof(struct iphdr) + 
                                                          sizeof(struct udphdr)];

  /*populating MAC Header for Response*/
  memcpy((void *)&eth_rsp_ptr->h_source, (const void *)&eth_ptr->h_dest,   6);
  memcpy((void *)&eth_rsp_ptr->h_dest,   (const void *)&eth_ptr->h_source, 6);
  eth_rsp_ptr->h_proto = eth_ptr->h_proto;

  /*populating IP Header for response*/ 
  ip_rsp_ptr->ip_len         = 0x5;
  ip_rsp_ptr->ip_ver         = 0x4;
  ip_rsp_ptr->ip_tos         = 0x00;
  /*to be updated later*/
  ip_rsp_ptr->ip_tot_len     = 0x00;
  ip_rsp_ptr->ip_id          = htons(random() % 65535);
  ip_rsp_ptr->ip_flag_offset = htons(0x1 << 14);
  ip_rsp_ptr->ip_ttl         = 0x10;
  ip_rsp_ptr->ip_proto       = 0x11;
  ip_rsp_ptr->ip_chksum      = 0x00;

  ip_rsp_ptr->ip_src_ip  = htonl(utility_ip_str_to_int((char *)pDnsCtx->ns1_ip));
  ip_rsp_ptr->ip_dest_ip = ip_ptr->ip_src_ip;

  /*populating UDP Header*/
  udp_rsp_ptr->udp_src_port  = udp_ptr->udp_dest_port;
  udp_rsp_ptr->udp_dest_port = udp_ptr->udp_src_port; 
  udp_rsp_ptr->udp_len       = 0x00;
  udp_rsp_ptr->udp_chksum    = 0x00;

  /*populating DNS Reply with RR*/
  dns_rsp_ptr->xid     = dns_ptr->xid;
  dns_rsp_ptr->qr      = 0x1;
  dns_rsp_ptr->opcode  = DNS_QUERY ;
  dns_rsp_ptr->aa      = 0x1;
  dns_rsp_ptr->tc      = 0x0;
  dns_rsp_ptr->rd      = dns_ptr->rd;
  dns_rsp_ptr->ra      = 0x00;
  dns_rsp_ptr->z       = 0x00;
  dns_rsp_ptr->rcode   = DNS_NO_ERROR;
  dns_rsp_ptr->qdcount = htons(0x01);
  dns_rsp_ptr->ancount = htons(0x02);
  dns_rsp_ptr->nscount = htons(0x01);
  dns_rsp_ptr->arcount = htons(0x00);

  /*populating DNS Payload*/
  offset = sizeof(struct dnshdr) +
           sizeof(struct udphdr) +
           sizeof(struct iphdr)  +
           sizeof(struct eth);

  /*copy query from request into response*/
  for(idx = 0; idx <pDnsCtx->qdata.qname_count; idx++) {
    rsp_ptr[offset++] = pDnsCtx->qdata.qname[idx].len;

    memcpy((void *)&rsp_ptr[offset], 
           pDnsCtx->qdata.qname[idx].value, 
           pDnsCtx->qdata.qname[idx].len);

    offset += pDnsCtx->qdata.qname[idx].len;
  }

  /*This marks the end of qname RR*/
  rsp_ptr[offset++] = 0;

  /*AN SECTION (1) - Answer Section of RR*/

  /*TYPE is A for Host Address*/
  rsp_ptr[offset++] = (A & 0xFF00) >> 8;
  rsp_ptr[offset++] = (A & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*domain name*/ 
  for(idx = 0; idx <pDnsCtx->qdata.qname_count; idx++) {
    rsp_ptr[offset++] = pDnsCtx->qdata.qname[idx].len;

    memcpy((void *)&rsp_ptr[offset], 
           pDnsCtx->qdata.qname[idx].value, 
           pDnsCtx->qdata.qname[idx].len);

    offset += pDnsCtx->qdata.qname[idx].len;
  }

  /*This marks the end of qname RR*/
  rsp_ptr[offset++] = 0;

  /*AN SECTION (1) - Answer Section of RR*/

  /*TYPE is A for Host Address*/
  rsp_ptr[offset++] = (A & 0xFF00) >> 8;
  rsp_ptr[offset++] = (A & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*Type is TTl in seconds*/
  rsp_ptr[offset++] = (0x0100 & 0xFF000000) >> 24;
  rsp_ptr[offset++] = (0x0100 & 0x00FF0000) >> 16;
  rsp_ptr[offset++] = (0x0100 & 0x0000FF00) >> 8;
  rsp_ptr[offset++] = (0x0100 & 0x000000FF);

  /*Type is RDLENGTH*/
  rsp_ptr[offset++] = (0x04 & 0xFF00) >> 8;
  rsp_ptr[offset++] = (0x04 & 0x00FF);

  /*Type is RDATA*/
  *((uint32_t *)&rsp_ptr[offset]) = htonl(utility_ip_str_to_int((char *)pDnsCtx->host_ip));
  offset += 4;
  /*AN Section (2) */
  rsp_ptr[offset++] = strlen((const char *)pDnsCtx->ns1_name);

  memcpy((void *)&rsp_ptr[offset], 
         pDnsCtx->ns1_name, 
         strlen((const char *)pDnsCtx->ns1_name));

  offset += strlen((const char *)pDnsCtx->ns1_name);

  rsp_ptr[offset++] = 0;
  /*TYPE it belongs to*/
  rsp_ptr[offset++] = (A & 0xFF00) >> 8;
  rsp_ptr[offset++] = (A & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*Type is TTl in seconds*/
  rsp_ptr[offset++] = (0x0100 & 0xFF000000) >> 24;
  rsp_ptr[offset++] = (0x0100 & 0x00FF0000) >> 16;
  rsp_ptr[offset++] = (0x0100 & 0x0000FF00) >> 8;
  rsp_ptr[offset++] = (0x0100 & 0x000000FF);
  
  rsp_ptr[offset++] = (0x04 & 0xFF00) >> 8;
  rsp_ptr[offset++] = (0x04 & 0x00FF);
  
  /*Type is RDATA*/

  *((uint32_t *)&rsp_ptr[offset]) = htonl(utility_ip_str_to_int((char *)pDnsCtx->ns1_ip));
  offset += 4;
 
  /*NS SECTION - Name Server Section of RR*/

  idx = strlen((const char *)pDnsCtx->ns1_name);
  rsp_ptr[offset++] = idx & 0xFF;
  memcpy((void *)&rsp_ptr[offset], pDnsCtx->ns1_name, idx);
  offset += idx;
  
  sscanf((const char *)pDnsCtx->domain_name, "%[^.].%s", label_str[0], label_str[1]);

  idx = strlen((const char *)label_str[0]);
  rsp_ptr[offset++] = idx & 0xFF;
  memcpy((void *)&rsp_ptr[offset], label_str[0], idx);
  offset += idx;

  idx = strlen((const char *)label_str[1]);
  rsp_ptr[offset++] = idx & 0xFF;
  memcpy((void *)&rsp_ptr[offset], (const void *)label_str[1], idx);
  offset += idx;
 
  /*marking the end of FQDN name for ns1*/
  rsp_ptr[offset++] = 0;

  /*TYPE it belongs to*/
  rsp_ptr[offset++] = (NS & 0xFF00) >> 8;
  rsp_ptr[offset++] = (NS & 0x00FF);

  /*CLASS is IN for Internet*/
  rsp_ptr[offset++] = (IN & 0xFF00) >> 8;
  rsp_ptr[offset++] = (IN & 0x00FF);

  /*Type is TTl in seconds*/
  rsp_ptr[offset++] = (0x0100 & 0xFF000000) >> 24;
  rsp_ptr[offset++] = (0x0100 & 0x00FF0000) >> 16;
  rsp_ptr[offset++] = (0x0100 & 0x0000FF00) >> 8;
  rsp_ptr[offset++] = (0x0100 & 0x000000FF);

  /*Type is RDLENGTH*/
  rsp_ptr[offset++] = (0x00 & 0xFF00) >> 8;
  rsp_ptr[offset++] = (0x00 & 0x00FF);
  

  /*populating length in respective Header filed*/ 
  ip_rsp_ptr->ip_tot_len = htons(offset - sizeof(struct eth));
  udp_rsp_ptr->udp_len   = htons(offset - (sizeof(struct eth) + sizeof(struct iphdr)));
  ip_rsp_ptr->ip_chksum  = utility_cksum((void *)ip_rsp_ptr,  (sizeof(unsigned int) * ip_rsp_ptr->ip_len));

  /*Populating pseudo header for UDP csum calculation*/
  pseudo_ptr = (unsigned char *)malloc(offset + 12);
  memset((void *)pseudo_ptr, 0, (offset + 12));
  
  memcpy((void *)&pseudo_ptr[0], (const void *)&ip_rsp_ptr->ip_dest_ip, 4);
  memcpy((void *)&pseudo_ptr[4], (const void *)&ip_rsp_ptr->ip_src_ip, 4);

  /*It's padded with zero*/
  pseudo_ptr[8]  = 0;

  /*Protocol is UDP*/
  pseudo_ptr[9]  = 17;

  /*Length of UDP Header + it's payload (DNS's Header + DNS Payload)*/
  pseudo_ptr[10] = (ntohs(udp_rsp_ptr->udp_len) >> 8) & 0xFF;
  pseudo_ptr[11] = ntohs(udp_rsp_ptr->udp_len) & 0xFF;

  memcpy((void *)&pseudo_ptr[12], 
         (const void *)&rsp_ptr[sizeof(struct eth) + sizeof(struct iphdr)], 
         ((offset + 12) - (sizeof(struct eth) + sizeof(struct iphdr))));
 
  udp_rsp_ptr->udp_chksum = utility_cksum((void *)pseudo_ptr, 
                                       ((offset + 12) - (sizeof(struct eth) + sizeof(struct iphdr))));
  write_eth_frame(fd, (uint8_t *)eth_rsp_ptr->h_dest, rr_reply, offset);

  free(pseudo_ptr);
  pseudo_ptr = NULL;

  return(0);
}/*dns_build_rr_reply*/


uint32_t dns_process_dns_query(int16_t fd, 
                               uint8_t *packet_ptr, 
                               uint16_t packet_length) {

  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  uint8_t  sql_query[512];
  uint8_t  domain_name[255];

  uint8_t  record[2][16][32];
  int32_t  row = 0;
  int32_t  col = 0;

  memset((void *)&domain_name, 0, sizeof(domain_name));

  snprintf((char *)domain_name, 
            sizeof(domain_name),
            "%s%s%s",
            pDnsCtx->qdata.qname[pDnsCtx->qdata.qname_count - 2].value,
            ".",
            pDnsCtx->qdata.qname[pDnsCtx->qdata.qname_count - 1].value);
   
  /*check if DNS query is for local DNS or external one.*/
  if(!strncmp((const char *)pDnsCtx->domain_name, 
              (const char *)domain_name, 
              strlen((const char *)pDnsCtx->domain_name))) {

    memset((void *)&sql_query, 0, sizeof(sql_query));
    snprintf((char *)sql_query, 
             sizeof(sql_query),
             "%s%s%s%s%s",
             "SELECT * FROM ",
             pDnsCtx->ip_allocation_table,
             " WHERE host_name ='",
             pDnsCtx->qdata.qname[0].value,
             "'");

    if(!db_exec_query((char *)sql_query)) {

      memset((void *)record, 0, (2 * 16 * 32));
      if(!db_process_query_result(&row, &col, (char ***)record)) {
 
        if(row) {
          memset((void *)pDnsCtx->host_ip, 0, sizeof(pDnsCtx->host_ip));
          snprintf(pDnsCtx->host_ip, sizeof(pDnsCtx->host_ip),
                   "%s.%s",
                   record[0][2],
                   record[0][3]);

          memset((void *)pDnsCtx->host_name, 0, sizeof(pDnsCtx->host_name));
          memcpy((void *)pDnsCtx->host_name, 
                 (const void *)pDnsCtx->qdata.qname[0].value, 
                 strlen((const char *)pDnsCtx->qdata.qname[0].value));

          /*Prepare the RR (Resource Record for DNS Reply*/
          dns_build_rr_reply(fd, packet_ptr, packet_length);

        } else {
          /*IP is not managed by this DHCP Server*/
          dns_perform_snat(fd, packet_ptr, packet_length);
        }
      }
    }
  } else {
    dns_perform_snat(fd, packet_ptr, packet_length);
  }

  return(0);
}/*dns_process_dns_query*/


void dns_display_char(uint8_t *label, uint16_t label_len) {
  uint16_t idx = 0;

  fprintf(stderr, "\nThe Length is %d\n", label_len);

  for(idx = 0; idx < label_len; idx++) {
    fprintf(stderr, "%c", label[idx]);
  }

  fprintf(stderr, "\n");
}/*dns_display_char*/

uint32_t dns_get_qname_len(void) {
  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  uint32_t idx = 0;
  uint32_t tot_len = 0;

  for(idx = 0; idx <pDnsCtx->qdata.qname_count; idx++) {
    tot_len += pDnsCtx->qdata.qname[idx].len;    
  }

  return(tot_len);
}/*dns_get_qname_len*/


uint32_t dns_parse_qdsection(int16_t fd, 
                             uint8_t *packet_ptr, 
                             uint16_t packet_length) {

  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  uint8_t *pQdata    = NULL;
  uint8_t  idx       = 0;
  uint16_t offset    = 0;

  pQdata = (uint8_t *)&packet_ptr[sizeof(struct eth)     + 
                                  sizeof(struct iphdr)   + 
                                  sizeof(struct udphdr)  + 
                                  sizeof(struct dnshdr)];


  memset((void *)&pDnsCtx->qdata, 0, sizeof(dns_qddata_t));

  pDnsCtx->qdata.qname[idx].len = pQdata[offset++];

  while(pDnsCtx->qdata.qname[idx].len > 0) {

    memset((void *)pDnsCtx->qdata.qname[idx].value, 
           0, 
           sizeof(pDnsCtx->qdata.qname[idx].value));

    memcpy((void *)pDnsCtx->qdata.qname[idx].value, 
           (void *)&pQdata[offset], 
           pDnsCtx->qdata.qname[idx].len);

    offset += pDnsCtx->qdata.qname[idx].len;
    idx += 1; 
    pDnsCtx->qdata.qname[idx].len = pQdata[offset++];
  }
        
  pDnsCtx->qdata.qname_count = idx;
  pDnsCtx->qdata.qtype = ntohs(*(uint16_t *)&pQdata[offset]);

  offset += 2;
  pDnsCtx->qdata.qclass = ntohs(*(uint16_t *)&pQdata[offset]);
  
  dns_process_dns_query(fd, packet_ptr, packet_length);

  return(offset);
}/*dns_parse_qdsection*/


uint32_t dns_process_ansection(int16_t   fd, 
                               uint8_t  *packet_ptr, 
                               uint16_t  packet_length) {
  dns_ctx_t *pDnsCtx = &dns_ctx_g;
  uint8_t *pAndata  = NULL;
  uint8_t  idx      = 0;
  uint16_t offset   = 0;

        
  pAndata = (uint8_t *)&packet_ptr[sizeof(struct eth)    + 
                                   sizeof(struct iphdr)  + 
                                   sizeof(struct udphdr) + 
                                   sizeof(struct dnshdr) +
                                   sizeof(pDnsCtx->qdata.qtype) +
                                   sizeof(pDnsCtx->qdata.qclass) +
                                   dns_get_qname_len()];

  memset((void *)&pDnsCtx->andata, 0, sizeof(dns_andata_t));
  pDnsCtx->andata.name[idx].len = pAndata[offset++];
  
  fprintf(stderr, "\nAnswer Section\n");

  while(pDnsCtx->andata.name[idx].len > 0) {
    memcpy((void *)&pDnsCtx->andata.name[idx].value, (void *)&pAndata[offset], pDnsCtx->andata.name[idx].len);
    offset += pDnsCtx->andata.name[idx].len;
    dns_display_char(pDnsCtx->andata.name[idx].value, pDnsCtx->andata.name[idx].len);
    idx += 1; 

    pDnsCtx->andata.name[idx].len = pAndata[offset++];
  }
  /*A length of zero is meant for root node in domain hierarchy*/
  offset++;      
  pDnsCtx->andata.name_count = idx;
  pDnsCtx->andata.type = ntohs(*(uint16_t *)&pAndata[offset]);

  offset += 2;
  pDnsCtx->andata.rdata_class = ntohs(*(uint16_t *)&pAndata[offset]);
  offset += 2;
  pDnsCtx->andata.ttl = ntohl(*(uint16_t *)&pAndata[offset]);
  offset += 4;

  pDnsCtx->andata.rdlength = ntohs(*(uint16_t *)&pAndata[offset]);
  offset += 2;

  memcpy((void *)&pDnsCtx->andata.rdata, (void *)&pAndata[offset], pDnsCtx->andata.rdlength);
  offset += pDnsCtx->andata.rdlength;

  return(offset);   
}/*dns_process_ansection*/

uint32_t dns_process_nssection(int16_t   fd, 
                               uint8_t *packet_ptr, 
                               uint16_t  packet_length) {
  return(0);
}/*dns_process_nssection*/


uint32_t dns_process_arsection(int16_t   fd, 
                               uint8_t *packet_ptr, 
                               uint16_t  packet_length) {
  return(0);
}/*dns_process_arsection*/


uint32_t dns_main(int16_t fd, 
                  uint8_t *packet_ptr, 
                  uint16_t packet_length) {

  uint32_t offset = 0;
  struct dnshdr  *dns_ptr = (struct dnshdr *)&packet_ptr[sizeof(struct eth) + 
                            sizeof(struct iphdr) + 
                            sizeof(struct udphdr)];
  
  
  /*Is it Query (a value 0) or Answer (a value 1)?*/
  if(dns_ptr->qr) {
    return(dns_perform_dnat(fd, packet_ptr, packet_length));
  }

  switch(dns_ptr->opcode) {
    case DNS_QUERY:
      /*Is it for local DNS or the public one*/
      if((ntohs(dns_ptr->qdcount) > 0) && (!dns_ptr->qr)) {
       offset = dns_parse_qdsection(fd, packet_ptr, packet_length);
      }
      
      if((ntohs(dns_ptr->ancount > 0)) && (dns_ptr->qr)) {
        offset = dns_process_ansection(fd, packet_ptr, packet_length);
      }
    
      if(ntohs(dns_ptr->nscount > 0)) {
        offset = dns_process_nssection(fd, packet_ptr, packet_length); 
      }
      
      if(ntohs(dns_ptr->arcount > 0)) {
        offset = dns_process_arsection(fd, packet_ptr, packet_length);
      }
    break;

    case DNS_INVERSE_QUERY:
    break;
    case DNS_STATUS:
    break;
    default:
    break;
  }
  (void)offset;
  return(0);
}/*dns_main*/


#endif /* __DNS_C__ */
