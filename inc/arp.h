#ifndef __ARP_H__
#define __ARP_H__

struct arp_cache_t {
  uint32_t           source_ip;
  uint16_t           source_port;
  uint8_t            source_mac[6];
  uint32_t           dest_ip;
  uint16_t           dest_port;
  uint8_t            dest_mac[6];
  uint16_t           ttl;
  struct arp_cache_t *next; 
};

typedef struct arp_cache_t arp_cache_tt;

typedef enum {
  ARP_RESERVED,
  ARP_REQUEST,
  ARP_REPLY,
  RARP_REQUEST,
  RARP_REPLY
}arp_op_code_t;

typedef struct {
  uint8_t      ip_str[32];
  uint8_t      eth_name[8];
  uint8_t      mac[32];
  uint32_t     ip_addr;
  /*ARP Request time out*/
  timer_t      arp_req_tid;
  uint8_t      dns1_str[16];
  uint8_t      dns2_str[16];
  arp_cache_tt arp_cache;

}arp_ctx_t;


uint32_t arp_build_ARP_request(uint32_t dest_ip);

uint32_t arp_process_ARP(int32_t fd, 
                         char *packet_ptr, 
                         uint16_t packet_length);


int arp_process_ARP_request(int32_t fd, char *packet_ptr, unsigned int packet_length);

uint32_t arp_process_ARP_reply(uint32_t fd, 
                               uint8_t *packet_ptr, 
                               uint16_t packet_length);

uint32_t arp_init(uint8_t *table_name, uint32_t dns1, uint32_t dns2);

uint32_t arp_get_mac(uint8_t *eth_name, uint8_t *mac);
#endif
