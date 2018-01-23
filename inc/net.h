#ifndef __NET_H__
#define __NET_H__

typedef int (*pFn) (int fd, unsigned char *pPacket, unsigned int packet_len);

/*Data structure definition*/
typedef struct {
  int                raw_fd;
  /*MAC address of the ethernet interface*/
  char               src_hwaddr[6];
  /*Ethernet Interface Index*/
  char               intf_idx;
  /*Maximum Trasfer Unit in bytes - 1500 for Ethernet Frame*/
  int                intf_mtu;
  /*Ethernet Interface name - eth0 or eth1 etc*/
  char               intf_name[8];
  /*The configured flags for ethernet interfcae*/
  int                intf_flags;
  struct sockaddr_ll addr;
  socklen_t          addr_len;
  unsigned char      packet[1500];
  unsigned int       packet_len;

  /*For WAN Interface*/
  int                wan_fd;
  
  /*For Timerexpiry Interface*/
  fd_set             timer_fd;
  int32_t (*callback)(void *);
  void *callback_ctx;
}net_ctx_t;

/*Function Prototype*/
int open_eth (char *eth_name);

int ndelay_on (int fd);

int coe (int fd);

int read_eth_frame (int fd, unsigned char *packet, unsigned int *packet_len);

int write_eth_frame (int fd, unsigned char *dst_mac, unsigned char *packet, unsigned int packet_len);

int net_main(pFn recv_cb, 
             unsigned int time_in_sec, 
             unsigned int time_in_ms);

void set_timer_fd(void);

void net_set_timer_fd(int32_t (*pCb)(void *), void *ctx);

#endif
