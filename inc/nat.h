#ifndef __NAT_H__
#define __NAT_H__

#define DD_S_NAT_CACHE_TABLE "nat_cache_table"
#define DD_S_SERVICE_CONF_TABLE "service_conf_table"

/********************************************************************
 *  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
   |15_14_13_12_11_10_9_8_7_6_5_4_3_2_1_0| 
   |_|_ _ _ _ _ _ _|_ _ _ _ _ _ _ _ _ _ _|
   bit15 is set to 1
   bits14 - bit10 are used to designate the NAT Protocol
   bits9  - bit0 are to designate the source port
 */
typedef enum {
  NAT_PROTO_UDP  = 1,
  NAT_PROTO_TCP  = 2,
  NAU_PROTO_DNS  = 3,
  NAT_PROTO_ICMP = 4,
  NAT_PROTO_IGMP = 5,
  NAT_PROTO_RTP  = 6,
  NAT_PROTO_RTCP = 7,
  NAT_PROTO_MAX  = (1 << 5)
  
}nat_protocol_type_t;

typedef enum {
  DIR_LAN_TO_WAN = 0,
  DIR_WAN_TO_LAN = 1
}nat_dir_t;

typedef struct {
  uint8_t  interface_name[32];
  uint32_t ip_addr;
  uint32_t dns1;
  uint32_t dns2;
  uint8_t  ip_addr_str[32];
  uint8_t  mac_addr[6];
  uint8_t  mac_str[16];
  uint32_t uam_ip;
  uint16_t uam_port;
  uint8_t uam_ip_str[32];
  uint16_t redir_port;
}nat_ctx_t;

#endif /*__NAT_H__*/
