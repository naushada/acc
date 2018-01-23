/** @file nat.c
 *  @brief This file contains the source natting and destination natting. 
 *
 *  This contains the core logic of source natting and destination natting
 *  along with other subfunction which facillitates source and destination natting
 *  
 *
 *  @author Mohd. Naushad Ahmed
 *  @bug No known bugs.
 */

#ifndef __NAT_C__
#define __NAT_C__

#include <type.h>
#include <transport.h>
#include <common.h>
#include <nat.h>
#include <tcp.h>

/********************************************************************
 *Extern Declaration
 ********************************************************************/
extern int db_process_query_result(int32_t *row_count, 
                                   int32_t *column_count, 
                                   char ***result);

extern int db_exec_query(uint8_t *sql_query);

extern unsigned short utility_dhcp_cksum(void *pkt_ptr, size_t pkt_len);

extern int utility_hex_dump(uint8_t  *packet, 
                    uint16_t packet_len);

extern uint16_t tcp_checksum(uint8_t *packet_ptr);

extern uint16_t utility_udp_checksum(uint8_t *packet_ptr);


extern int32_t subscriber_is_authenticated(uint32_t subscriber_ip); 

extern int32_t subscriber_add_subscriber(uint32_t src_ip, 
                                  uint8_t *src_mac_ptr, 
                                  uint16_t src_port);

extern int32_t subscriber_add_info(uint32_t ip_address,
                                   uint16_t dest_port,
                                   uint8_t *uri,
                                   uint8_t *auth_state);

extern int32_t subscriber_get_auth_state(uint32_t ip_address, 
                                         uint8_t *auth_state);

extern int32_t subscriber_update_auth_state(uint32_t ip_address, 
                                            uint8_t *auth_state);

extern int32_t dhcp_get_mac(uint32_t ip_address, uint8_t *mac_addr);
/********************************************************************
 * Global Instance
 ********************************************************************/
nat_ctx_t nat_ctx_g;

/********************************************************************
 *Function Definition
 ********************************************************************/
uint16_t nat_src_port_n_dest_ip_found(uint16_t src_port, 
                                      uint32_t dest_ip, 
                                      uint16_t *nat_port) {
  uint8_t sql_query[256];
  int32_t row = 0;
  int32_t col = 0;
  uint8_t record[2][16][32];
  uint8_t ip_str[64];

  memset((void *)sql_query, 0, sizeof(sql_query));
  memset((void *)ip_str, 0, sizeof(ip_str));

  utility_ip_int_to_str(dest_ip, ip_str);

  snprintf((char *)sql_query, 
           sizeof(sql_query), 
           "%s%s%s%d%s"
           "%s%s",
           "SELECT * FROM ",
           DD_S_NAT_CACHE_TABLE,
           " WHERE (src_port='",
           src_port,
           "' AND dest_ip='",
           ip_str,
           "')");

  if(!db_exec_query(sql_query)) {
    /*Process the Result*/
    memset((void *)record, 0, (sizeof(uint8_t) * 2 * 16 * 32));
    if(!db_process_query_result(&row, &col, (char ***)record)) {

      if(row) {
        /*dest_port is nat_port*/
        sscanf((const char *)record[0][4], "%d", (int32_t *)nat_port);
        return(row);
      }
    }
  }
  return(0);
}/*nat_src_port_n_dest_ip_found*/

int32_t nat_init_uam_param(void) {
  uint8_t sql_query[255];
  uint32_t row;
  uint32_t col;
  uint8_t record[2][16][32];

  nat_ctx_t *pNatCtx = &nat_ctx_g;
  
  memset((void *)sql_query, 0, sizeof(sql_query));
  
  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s",
           "SELECT * FROM ",
           DD_S_SERVICE_CONF_TABLE,
           " WHERE service_type='UAM_SERVER'");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, 2*16*32);
    if(!db_process_query_result(&row, &col, (char ***)record)) {
      if(row) {
        strncpy(pNatCtx->uam_ip_str, 
                (const char *)record[0][0], 
                strlen((const char *)record[0][0]));
        pNatCtx->uam_ip = utility_ip_str_to_int((uint8_t *)pNatCtx->uam_ip_str);

        sscanf((const char *)record[0][1], "%d", (int32_t *)&pNatCtx->uam_port);
        
        return(0);
      }
    }
  }
  return(-1);

}/*nat_init_uam_param*/

/** @brief 
 * 
 *
 *
 *  @param 
 *  @return 
 */
int32_t nat_init(uint8_t *interface_name,
                 uint32_t dhcp_server_ip,
                 uint32_t dns1,
                 uint32_t dns2,
                 uint16_t redir_port) {

  int32_t fd;
  struct ifreq ifr;
  nat_ctx_t *pNatCtx = &nat_ctx_g;
 
  strncpy((char *)ifr.ifr_name, 
          (const char *)interface_name, 
          IFNAMSIZ);

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(fd < 0) {
    perror("creation of socket failed\n");
    return(-1);
  }

  /*Retrieving MAC Address*/
  if(ioctl(fd, SIOCGIFHWADDR, &ifr)) {
    perror("\nFailed while retrieving MAC Address\n");
    return(-2); 
  }

  memcpy((void *)pNatCtx->mac_addr, 
         (const char *)ifr.ifr_hwaddr.sa_data, 
         IFNAMSIZ);

  pNatCtx->ip_addr = dhcp_server_ip;

  utility_ip_int_to_str(pNatCtx->ip_addr, 
                        (uint8_t *)pNatCtx->ip_addr_str);

  utility_mac_int_to_str(pNatCtx->mac_addr, pNatCtx->mac_str);

  strncpy((char *)pNatCtx->interface_name, 
          (const char *)ifr.ifr_name, 
          sizeof(pNatCtx->interface_name));

  pNatCtx->redir_port = redir_port;
  pNatCtx->dns1 = dns1;
  pNatCtx->dns2 = dns2;
  nat_init_uam_param();
 
  return(0);
}/*nat_init*/

int32_t nat_delete_cache(uint16_t dest_port,
                         uint32_t dest_ip) {
  uint8_t sql_query[255];
  int32_t ret = -1;
  uint8_t ipaddr_str[40];

  memset((void *)ipaddr_str, 0, sizeof(ipaddr_str));

  utility_ip_int_to_str(ntohl(dest_ip), ipaddr_str);

  ret = snprintf((char *)sql_query, 
                 sizeof(sql_query),
                 "%s%s%s%d%s"
                 "%s%s",
                 "DELETE FROM ",
                 DD_S_NAT_CACHE_TABLE,
                 " WHERE (src_port='",
                 dest_port,
                 "' AND dest_ip='",
                 ipaddr_str,
                 "')");

  if(db_exec_query(sql_query)) {
    fprintf(stderr, "\n%s:%d::Deletion of entry failed\n", __FILE__, __LINE__);
    return(-1);
  }
  (void)ret;
  return(0);

}/*nat_delete_cache*/


int32_t nat_update_cache(uint32_t ipaddr, 
                         uint8_t *mac_addr, 
                         uint16_t src_port, 
                         uint16_t nat_port,
                         uint32_t dest_ip) {
  int32_t ret = -1;
  uint8_t sql_query[256];
  int32_t row;
  int32_t col;
  int8_t  record[2][16][32];
  uint8_t mac_str[32];
  uint8_t ipaddr_str[32];
  uint8_t dest_ipaddr_str[32];

  memset((void *)mac_str, 0, sizeof(mac_str));
  memset((void *)ipaddr_str, 0, sizeof(ipaddr_str));

  utility_ip_int_to_str(ipaddr, ipaddr_str);
  utility_ip_int_to_str(dest_ip, dest_ipaddr_str);
  utility_mac_int_to_str(mac_addr, mac_str);
  //fprintf(stderr, "\n%s:%d src_ip %s dest_ip %s\n", __FILE__, __LINE__, ipaddr_str, dest_ipaddr_str);
  ret = snprintf((char *)sql_query, 
                sizeof(sql_query),
                "%s%s%s%s%s"
                "%s%s%d%s%s"
                "%s%d%s",
                "SELECT * FROM ",
                DD_S_NAT_CACHE_TABLE,
                " WHERE (src_ip='",
                ipaddr_str,
                "' AND src_mac='",
                mac_str,
                "' AND src_port='",
                src_port,
                "' AND dest_ip='",
                dest_ipaddr_str,
                "' AND dest_port='",
                nat_port,
                "')");

  if(db_exec_query((uint8_t *)sql_query)) {
    fprintf(stderr, "\n%s:%d Execution of SQL Query Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)&record, 0, 2*16*32);
  if(!db_process_query_result(&row, &col, (char ***)record)) {

    /*Process The Reqult*/
    if(!row) {
      /*No Record found , Insert it*/
      memset((void *)&sql_query, 0, sizeof(sql_query));

      ret = snprintf((char *)sql_query,
                    sizeof(sql_query),
                    "%s%s%s%s%s"
                    "%s%s%d%s%s"
                    "%s%d%s",
                    "INSERT INTO ",
                    DD_S_NAT_CACHE_TABLE,
                    " (src_ip, src_mac, src_port, dest_ip, dest_port) VALUES ('",
                    ipaddr_str,
                    "' , '",
                    mac_str,
                    "' , '",
                    src_port,
                    "' , '",
                    dest_ipaddr_str,
                    "' , '",
                    nat_port,
                    "')");

      if(db_exec_query((uint8_t *)sql_query)) {
        fprintf(stderr, "\n%s:%d Insertion to Database failed\n", __FILE__, __LINE__);
        return(-3);
      }
    }
  }
  (void)ret;
  return(0);
                
}/*nat_update_cache*/

int32_t nat_is_found_in_cache(uint16_t src_port,
                              uint32_t dest_ip) {
  uint8_t sql_query[255];
  int32_t row;
  int32_t col;
  uint8_t record[2][16][32];
  uint8_t dest_ip_str[32];

  memset((void *)dest_ip_str, 0, sizeof(dest_ip_str));
  utility_ip_int_to_str(dest_ip, dest_ip_str);

  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%d%s"
           "%s%s",
           "SELECT * FROM ",
           DD_S_NAT_CACHE_TABLE,
           " WHERE (src_port='",
           src_port,
           "' AND dest_ip='",
           dest_ip_str,
           "')");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, sizeof(record));
    row = 0, col = 0;
    if(!db_process_query_result(&row, &col, (char ***)record)) {
      return(row);
    }
  }

  return(0);
}/*nat_is_found_in_cache*/


int32_t nat_query_cache(uint16_t dest_port, 
                        uint32_t dest_ip, 
                        uint32_t *src_ip, 
                        uint8_t *mac_addr, 
                        uint16_t *src_port) {
  int32_t row;
  int32_t col;
  uint8_t record[2][16][32];
  uint8_t sql_query[256];
  uint8_t  dest_ip_str[40];

  memset((void *)dest_ip_str, 0, sizeof(dest_ip_str));
  utility_ip_int_to_str(dest_ip, dest_ip_str);

  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%d%s"
           "%s%s",
           "SELECT * FROM ",
           DD_S_NAT_CACHE_TABLE,
           " WHERE (src_port='",
           dest_port,
           "' AND src_ip='",
           dest_ip_str,
           "')");

  if(!db_exec_query((uint8_t *)sql_query)) {
    
    memset((void *)&record, 0, 2*16*32);
    row = 0;
    col = 0;
    if(!db_process_query_result(&row, &col, (char ***)record)) {
      if(row) {
        /*MAC Address*/
        utility_mac_str_to_int(record[0][1], mac_addr);
        /*dest Port would now become src port*/
        sscanf((const char *)record[0][4], "%d", (uint32_t *)src_port);
        /*src_ip will hold the value of dest ip*/
        *src_ip = utility_ip_str_to_int(record[0][3]);
        //fprintf(stderr, "\n%s:%d src_ip %X src_port %d\n", __FILE__, __LINE__, *src_ip, *src_port);
      } else {
        fprintf(stderr, "\n%s:%d no Row found for ip_address %s and nat_port %d\n%s\n", 
                        __FILE__,
                        __LINE__,
                        dest_ip_str,
                        dest_port,
                        sql_query);
      }
    }
  }
  return(row);

}/*nat_query_cache*/

int32_t nat_perform_snat(uint8_t  *packet_ptr, 
                         uint16_t packet_length, 
                         uint8_t  *snat_ptr, 
                         uint16_t *snat_length) {

  struct iphdr  *ip_ptr  = NULL;
  uint16_t nat_port = 0x0000;
  uint16_t ip_header_len = 0x0000;
  uint32_t dest_ip;

  nat_ctx_t *pNatCtx = &nat_ctx_g;

  struct eth *eth_ptr = (struct eth *)packet_ptr;

  /*what protocol is this? - what type of frame is followed the Ethernet Header*/
  if(0x0800 == htons(eth_ptr->h_proto)) {
    
    ip_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)];
    ip_header_len = (ip_ptr->ip_len * 4);

    /*copy ip header + its payload*/
    memcpy((void *)snat_ptr, 
           (const void *)&packet_ptr[sizeof(struct eth)], 
           ntohs(ip_ptr->ip_tot_len));

    *snat_length = ntohs(ip_ptr->ip_tot_len);

    switch(ip_ptr->ip_proto) {

      case IP_IGMP:
      break;
      case IP_TCP:
      {
        uint16_t src_port;
        uint16_t dest_port;
        uint32_t src_ip;
        uint8_t src_mac[6];
        struct tcp *tcphdr_ptr;
        struct iphdr *iphdr_ptr;
        uint8_t uri[255];
        uint8_t http_offset;
        int32_t ret;
        uint8_t dest_mac[6];

        memset((void *)src_mac, 0, sizeof(src_mac));

        iphdr_ptr = (struct iphdr *)snat_ptr;

        tcphdr_ptr = (struct tcp *)&snat_ptr[ip_header_len];
        pNatCtx->redir_port = 8080;

        src_port = ntohs(tcphdr_ptr->src_port);
        dest_port = ntohs(tcphdr_ptr->dest_port);
        
        src_ip = iphdr_ptr->ip_src_ip;
        dest_ip = iphdr_ptr->ip_dest_ip;
#if 0
        if((ntohl(dest_ip) == pNatCtx->uam_ip) &&
           (dest_port == pNatCtx->uam_port)) {
           //fprintf(stderr, "\n%s:%d Request for UAM let it go as is\n", __FILE__, __LINE__);
          /*do nothing*/
          break;
        }
        
        if((htonl(pNatCtx->ip_addr) == ntohl(dest_ip)) &&
           (dest_port == 54005)) {
           fprintf(stderr, "\n%s:%d Packet received for radiusC\n", __FILE__, __LINE__);
        }

        fprintf(stderr, "\n%s:%d dest_ip 0x%X uam ip 0x%X\n",
                        __FILE__,
                        __LINE__,
                        dest_ip,
                        pNatCtx->uam_ip);
#endif
        /*First IP Packets for port 80 or 443*/
        if((!subscriber_is_authenticated(src_ip)) && 
           (80 == dest_port || 443 == dest_port)) {

          subscriber_add_subscriber(src_ip, eth_ptr->h_source, src_port);

          /*This is the case when uamS is redirecting authstate_success to redir*/
          memcpy((void *)src_mac, eth_ptr->h_source, 6);

          nat_update_cache(src_ip, 
                           src_mac, 
                           src_port,
                           /*destination port*/
                           dest_port,
                           /*destination ip*/
                           dest_ip);
          /*Redirect Request to Redir Server for Authentication*/
          iphdr_ptr->ip_dest_ip = htonl(pNatCtx->ip_addr);
          iphdr_ptr->ip_src_ip = src_ip;

          /*IP Header checksum calculation - only header part*/
          iphdr_ptr->ip_chksum = 0;
          iphdr_ptr->ip_chksum = utility_cksum((void *)iphdr_ptr, ip_header_len);
          
          /*Modify the TCP headera as per need*/
          tcphdr_ptr->dest_port = htons(pNatCtx->redir_port);
          //fprintf(stderr, "New Connection 0x%X\n", pNatCtx->redir_port);
          tcphdr_ptr->check_sum = 0;
          tcphdr_ptr->check_sum = tcp_checksum(snat_ptr);

        } else if((1/*INPROGRESS*/ == subscriber_is_authenticated(src_ip)) && 
                  ((dest_port == 80) || 
                   (dest_port == 443))) {

          ret = nat_is_found_in_cache(src_port,
                              (uint32_t)dest_ip);
          if(ret) {
            fprintf(stderr, "\nOn Established connection\n");
            /*Established connection with redir*/
            iphdr_ptr->ip_dest_ip = htonl(pNatCtx->ip_addr);

            /*IP Header checksum calculation - only header part*/
            iphdr_ptr->ip_chksum = 0;
            iphdr_ptr->ip_chksum = utility_cksum((void *)iphdr_ptr, ip_header_len);
          
            /*Modify the TCP headera as per need*/
            tcphdr_ptr->dest_port = htons(pNatCtx->redir_port);
            tcphdr_ptr->check_sum = 0;
            tcphdr_ptr->check_sum = tcp_checksum(snat_ptr);
          } else {
            /*Reset the Connection*/
            uint16_t tmp_flags;
            /*swap the ip Address*/ 
            iphdr_ptr->ip_dest_ip = src_ip;
            iphdr_ptr->ip_src_ip = dest_ip;

            /*IP Header checksum calculation - only header part*/
            iphdr_ptr->ip_chksum = 0;
            iphdr_ptr->ip_chksum = utility_cksum((void *)iphdr_ptr, ip_header_len);
            
            /*Modify The TCP Header*/
            tcphdr_ptr->dest_port = htons(src_port);
            tcphdr_ptr->src_port = htons(dest_port);
            tcphdr_ptr->seq_num = tcphdr_ptr->ack_number;
            tcphdr_ptr->ack_number = 0;
            /*Reset the connection*/
            tmp_flags = ntohs(tcphdr_ptr->flags);
            tmp_flags = htons((tmp_flags & ~(0x3F)) | TCP_RST_BIT);
            tcphdr_ptr->flags = tmp_flags;
            #if 0
              if(tmp_flags & (TCP_FIN_BIT | TCP_ACK_BIT) == (TCP_FIN_BIT | TCP_ACK_BIT)) {
              //fprintf(stderr, "\nFIN and ACK bits are set\n");
            }
            #endif
            tcphdr_ptr->check_sum = 0;
            tcphdr_ptr->check_sum = tcp_checksum(snat_ptr);
          }
        } else if((1/*INPROGRESS*/ == subscriber_is_authenticated(src_ip)) && 
                  (dest_port != pNatCtx->uam_port))  {
          /*Reset the incoming connection*/
          uint16_t tmp_flags;

          /*Reset the Connection*/
          #if 0
          fprintf(stderr, "\n%s:%d Resetting the Connection dest_ip 0x%X uam_ip 0x%X ip_addr 0x%X\n", 
                           __FILE__, 
                           __LINE__,
                           dest_ip,
                           pNatCtx->uam_ip,
                           pNatCtx->ip_addr);
          #endif

          /*swap the ip Address*/ 
          iphdr_ptr->ip_dest_ip = src_ip;
          iphdr_ptr->ip_src_ip = dest_ip;

          /*IP Header checksum calculation - only header part*/
          iphdr_ptr->ip_chksum = 0;
          iphdr_ptr->ip_chksum = utility_cksum((void *)iphdr_ptr, ip_header_len);
            
          /*Modify The TCP Header*/
          tcphdr_ptr->dest_port = htons(src_port);
          tcphdr_ptr->src_port = htons(dest_port);
          tcphdr_ptr->window = 0;
          /*Reset the connection*/
          tmp_flags = htons(ntohs(tcphdr_ptr->flags) | TCP_RST_BIT);
          #if 0
            if(tmp_flags & (TCP_FIN_BIT | TCP_ACK_BIT) == (TCP_FIN_BIT | TCP_ACK_BIT)) {
            //fprintf(stderr, "\nFIN and ACK bits are set\n");
          }
          #endif
          tcphdr_ptr->check_sum = 0;
          tcphdr_ptr->check_sum = tcp_checksum(snat_ptr);

        } else if(2/*SUCCESS*/ == subscriber_is_authenticated(src_ip)) { 
          /*Do the accounting for authenticated subscriber*/
          fprintf(stderr, "\n%s:%d User %X is authenticated\n", 
                          __FILE__,
                          __LINE__,
                          src_ip);
        }
      } 
      break;

      case IP_UDP:
      {
        struct iphdr *iphdr_ptr = (struct iphdr *)snat_ptr;
        struct udphdr *udphdr_ptr = (struct udphdr *)&snat_ptr[ip_header_len];

        /*Message structure is based on destination UDP Port*/
        if(53 == ntohs(udphdr_ptr->udp_dest_port)) {
          /*DNS Query*/

          /*Change the destination ip-address*/
          iphdr_ptr->ip_dest_ip = htonl(pNatCtx->dns1);

          iphdr_ptr->ip_chksum = 0;
          iphdr_ptr->ip_chksum = utility_cksum((void *)iphdr_ptr, ip_header_len);

          /*Computing UDP Checksum*/
          udphdr_ptr->udp_chksum = 0;
          udphdr_ptr->udp_chksum  = utility_udp_checksum(snat_ptr);
        }
      }
      break;

      default:
      break; 
    }
  }
  return(0);

}/*dns_perform_snat*/

/** @brief 
 *  
 *
 *  @param 
 *  @return 
 */
int32_t nat_perform_dnat(uint8_t *packet_ptr, 
                         uint16_t packet_length,
                         uint8_t *dnat_ptr,
                         uint16_t *dnat_length) {

  uint16_t ip_header_len = 0x00;
  uint16_t nat_port = 0x00;
  uint16_t src_port = 0x00;
  int32_t ret = -1;

  nat_ctx_t *pNatCtx = &nat_ctx_g;

  /*copy the received ip packet into dnat_ptr*/
  memcpy((void *)&dnat_ptr[sizeof(struct eth)], 
         (const void *)packet_ptr, 
         packet_length);
  *dnat_length = packet_length + sizeof(struct eth);
 
  struct iphdr *dnat_iphdr_ptr = (struct iphdr *)&dnat_ptr[sizeof(struct eth)];
  ip_header_len = (4 * dnat_iphdr_ptr->ip_len);

  /*Populating Ethernet Header for IP Protocol*/
  struct eth *dnat_eth_ptr = (struct eth *)dnat_ptr;

  dhcp_get_mac(dnat_iphdr_ptr->ip_dest_ip, 
               dnat_eth_ptr->h_dest);

  memcpy((void *)dnat_eth_ptr->h_source, 
         (const void *)pNatCtx->mac_addr, 
         6);

  dnat_eth_ptr->h_proto = htons(0x0800);
      
  switch(dnat_iphdr_ptr->ip_proto) {
    case IP_IGMP:
    break;
    case IP_TCP:
    {
      uint8_t dest_mac[6];
      uint16_t dest_port;
      uint16_t src_port;
      uint32_t src_ip = 0;
      uint32_t dest_ip = 0;
      uint8_t tmp_flags = 0;

      struct iphdr *iphdr_ptr = NULL;
      struct tcp *tcphdr_ptr = NULL;

      iphdr_ptr = (struct iphdr *)&dnat_ptr[sizeof(struct eth)];

      dest_ip = iphdr_ptr->ip_dest_ip;
      src_ip = ntohl(iphdr_ptr->ip_src_ip);

      tcphdr_ptr = (struct tcp *)&dnat_ptr[sizeof(struct eth) + ip_header_len];

      dest_port = ntohs(tcphdr_ptr->dest_port);
      src_port = ntohs(tcphdr_ptr->src_port);

      /*Whether dest_ip (subscriber is authenticated or not*/
      if(2/*SUCCESS*/ == subscriber_is_authenticated(dest_ip)) {
        /*Delete cache for dest_ip if found*/
        memset((void *)dest_mac, 0, sizeof(dest_mac));
        /*Retrieve the IP, MAC from cache based on nat_port*/
        ret = nat_query_cache(dest_port,
                              (uint32_t)dest_ip, 
                              /*destination ip before snat*/
                              (uint32_t *)&src_ip,
                              (uint8_t *)dest_mac,
                              (uint16_t *)&src_port);
        if(ret) {
          /*Entry in cache table found, delete it.*/
          nat_delete_cache(dest_port, src_ip);
        }
        /*Let the packet go as is*/
      } else if(((!subscriber_is_authenticated(dest_ip)) || 
                 (1/*INPROGRESS*/ == subscriber_is_authenticated(dest_ip))) && 
                 (src_port == pNatCtx->redir_port)) {

        /*Reply is from UAM Server*/
        fprintf(stderr, "\n(nat.c)Reply From UAM Server (src_ip 0x%X) uam_ip 0x%X\n",
                        src_ip, pNatCtx->uam_ip);

        /*Retrieve the IP, MAC from cache based on nat_port*/
        ret = nat_query_cache(dest_port,
                              (uint32_t)dest_ip, 
                              (uint32_t *)&src_ip,
                              (uint8_t *)dest_mac,
                              (uint16_t *)&src_port);
     
        /*Modifying the destination IP Address*/
        iphdr_ptr->ip_src_ip = htonl(src_ip);
        iphdr_ptr->ip_chksum = 0;
        iphdr_ptr->ip_chksum = utility_cksum(iphdr_ptr, ip_header_len); 

        /*TCP Dest Port Modification*/
        tcphdr_ptr->src_port = htons(src_port);
        /*checksum field has to be reset before computing it.*/
        tcphdr_ptr->check_sum = 0;
        tcphdr_ptr->check_sum = tcp_checksum(&dnat_ptr[sizeof(struct eth)]);

      } 
         
      #if 0
      tmp_flags = ntohs(tcphdr_ptr->flags) & 0x3F;

      if(tmp_flags & (TCP_FIN_BIT | TCP_ACK_BIT) == (TCP_FIN_BIT | TCP_ACK_BIT)) {
        //fprintf(stderr, "\nFIN and ACK bits are set\n");
      }
      #endif
    }
    break;

    case IP_UDP:
    {
      struct udphdr *dnat_udphdr_ptr = (struct udphdr *)&dnat_ptr[sizeof(struct eth) + ip_header_len];
 
      dnat_iphdr_ptr->ip_src_ip = htonl(pNatCtx->ip_addr);
      
      /*IP Header checksum*/
      dnat_iphdr_ptr->ip_chksum = 0;
      dnat_iphdr_ptr->ip_chksum = utility_cksum((void *)dnat_iphdr_ptr, ip_header_len);

      /*Computing UDP Checksum*/
      dnat_udphdr_ptr->udp_chksum = 0;
      dnat_udphdr_ptr->udp_chksum  = utility_udp_checksum(&dnat_ptr[sizeof(struct eth)]);
    }
    break;

    default:
    break;
  }
  return(0);

}/*dns_perform_dnat*/


#endif /* __NAT_C__ */
