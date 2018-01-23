#ifndef __NET_C__
#define __NET_C__


#include <common.h>
#include <net.h>

/********************************************************************
 * Extern Declaration
 ********************************************************************/

/********************************************************************
 * Global Instance creation
 ********************************************************************/
net_ctx_t net_ctx_g;

/********************************************************************
 *Function Definition
 ********************************************************************/
int32_t net_setaddr(uint8_t *interface_name,
                    uint32_t ip_addr, 
                    uint32_t netmask_addr) {
  int32_t fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  memset((void *)&ifr, 0, sizeof(struct ifreq));
  strncpy((char *)ifr.ifr_name, (const char *)interface_name, IFNAMSIZ);

  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;
  ifr.ifr_netmask.sa_family = AF_INET;

  /*Make sure to null terminate*/
  ifr.ifr_name[IFNAMSIZ-1] = 0;

  ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = ip_addr;

  if (ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0) {
    fprintf(stderr, "Setting of interface address failed\n");
    close(fd);
    return(-1);
  }
  
  if(netmask_addr) {
    ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr = netmask_addr;

    if(ioctl(fd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
      fprintf(stderr, "\n%s:%d Setting of interface NETMASK failed\n", __FILE__, __LINE__);
      perror("netmask failed");
      close(fd);
      return(-2);
    }
  }

  close(fd);
  return(0);
}/*net_setaddr*/


void net_set_timer_fd(int32_t (*pCb)(void *), void *ctx) {
  net_ctx_t *pNetCtx = &net_ctx_g;
  pNetCtx->callback = pCb;
  pNetCtx->callback_ctx = ctx;
  FD_SET(pNetCtx->raw_fd, &pNetCtx->timer_fd);

}/*set_timer_fd*/

int open_eth(char *eth_name) {
  int fd = -1;
  int option = 0;
  int ifindex = 0;
  char hwaddr[6];
  
  net_ctx_t *pNetCtx = &net_ctx_g;

  struct ifreq ifr;
  struct sockaddr_ll sa;
  
  /*RAW ethernet Socket*/ 
  fd = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_ALL));

  if (fd < 0) {
    fprintf(stderr, "\nopen of socket failed");
    return(fd);  
  }
  pNetCtx->raw_fd = fd;

  /*non-blocking socket*/
  ndelay_on(fd);
  /*close on exit*/
  coe(fd);
  
  option = 1;
  setsockopt(fd, SOL_SOCKET, TCP_NODELAY,
		       &option, sizeof(option));

  /*Enable to receive/Transmit Broadcast Frame*/
  option = 1;
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
		       &option, sizeof(option));

  /*Initializing to zero*/
  memset((void *)&ifr, 0, sizeof(ifr));
  strncpy((char *)ifr.ifr_name, (const char *)eth_name, sizeof(ifr.ifr_name));
  /*Remembering int into global data structure*/
  strncpy((char *)pNetCtx->intf_name, (const char *)eth_name, sizeof(pNetCtx->intf_name));

  /*Retrieving MAC Address*/
  ioctl(fd, SIOCGIFHWADDR, &ifr);

  if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
     memset((void *)hwaddr, 0, sizeof(hwaddr));
     memcpy((void *)hwaddr, (const void *)ifr.ifr_hwaddr.sa_data, ETH_ALEN);
     /*Remembering int into global data structure*/
     memcpy((void *)pNetCtx->src_hwaddr, (const void *)ifr.ifr_hwaddr.sa_data, ETH_ALEN);
  }
  
  /* Get ifindex */
  strncpy((char *)ifr.ifr_name, (const char *)eth_name, sizeof(ifr.ifr_name));

  if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
    fprintf(stderr, "\nioctl failed");
    syslog(LOG_ERR, "%s: ioctl(SIOCFIGINDEX) failed", strerror(errno));
  }
  ifindex = ifr.ifr_ifindex;
  pNetCtx->intf_idx = ifindex;

  /* Set interface in promisc mode */
  struct packet_mreq mr;

  memset((void *)&ifr, 0, sizeof(ifr));
  strncpy((char *)ifr.ifr_name, (const char *)eth_name, sizeof(ifr.ifr_name));

  if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
    syslog(LOG_ERR, "%s: ioctl(SIOCGIFFLAGS)", strerror(errno));
  } else {
    ifr.ifr_flags |= (IFF_PROMISC | IFF_NOARP);
    pNetCtx->intf_flags = ifr.ifr_flags;

    if (ioctl (fd, SIOCSIFFLAGS, &ifr) == -1) {
      syslog(LOG_ERR, "%s: Could not set flag IFF_PROMISC", strerror(errno));
    }
  }

  memset((void *)&mr, 0, sizeof(mr));
  mr.mr_ifindex = ifindex;
  mr.mr_type    = PACKET_MR_PROMISC;

  if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       (char *)&mr, sizeof(mr)) < 0)
    return -1;

  /* Bind to particular interface */
  memset((void *)&sa, 0, sizeof(sa));
  sa.sll_family   = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex  = ifindex;

  if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
    syslog(LOG_ERR, "%s: bind(sockfd=%d) failed", strerror(errno), fd);
    return -1;
  }

  return(0);

}/*open_eth*/


int ndelay_on (int fd) {
  int got = fcntl(fd, F_GETFL);
  return (got == -1) ? -1 : fcntl(fd, F_SETFL, got | O_NONBLOCK);
}/*ndelay_on*/


int coe (int fd) {
  register int flags = fcntl(fd, F_GETFD, 0);
  if (flags == -1) return -1;
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}/*coe*/

int read_eth_frame (int fd, unsigned char *packet, unsigned int *packet_len) {
  int ret = -1;
  int max_len = 1500;
  net_ctx_t *pNetCtx = &net_ctx_g;

  if ((NULL == packet) ||
      (NULL == packet_len)) {
    return (ret);
  }

  do {
    ret = recvfrom (fd, 
                    packet, 
                    max_len, 
                    0, 
                    (struct sockaddr *)&pNetCtx->addr, 
                    &pNetCtx->addr_len);

  }while((ret == -1) && (errno == EINTR));

  *packet_len = ret;
  return(ret);
}/*read_eth_frame*/

int write_eth_frame (int fd, 
                     unsigned char *dst_mac, 
                     unsigned char *packet, 
                     unsigned int packet_len) {
  int ret = -1;
  net_ctx_t *pNetCtx = &net_ctx_g;
  struct sockaddr_ll sa;

  if (NULL == packet) {
    return (-1);
  }
  memset((void *)&sa, 0, sizeof(sa));
  sa.sll_family   = AF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex  = pNetCtx->intf_idx;
  sa.sll_halen    = ETH_ALEN;
  memcpy((void *)sa.sll_addr, (void *)dst_mac, ETH_ALEN);

  pNetCtx->addr_len = sizeof(struct sockaddr_ll);

  do {
    ret = sendto (fd, 
                  packet, 
                  packet_len, 
                  0, 
                  (struct sockaddr *)&sa, 
                  pNetCtx->addr_len);

  }while((ret == -1) && (errno == EINTR));
 
  if(ret < 0) {
    perror("sendto Failed:");
  }
  return (ret);
}/*write_eth_frame*/

int32_t net_get_dhcp_fd(void) {
  net_ctx_t *pNetCtx = &net_ctx_g;

  return(pNetCtx->raw_fd);
}/*net_get_dhcp_fd*/

int net_main(pFn recv_cb, 
             unsigned int time_in_sec, 
             unsigned int time_in_ms) {

  struct timeval to;
  int ret = -1;
  int max_fd;
  fd_set rd;

  net_ctx_t *pNetCtx = &net_ctx_g;
  FD_ZERO(&rd);
  FD_ZERO(&pNetCtx->timer_fd);

  for(;;) {
 
    FD_SET(pNetCtx->raw_fd, &rd);
    max_fd = pNetCtx->raw_fd;
    to.tv_sec  = time_in_sec;
    /*time in micro second*/
    to.tv_usec = time_in_ms;

    ret = select((max_fd + 1), 
                 (fd_set *)&rd, 
                 (fd_set *)&pNetCtx->timer_fd, 
                 NULL, 
                 &to);

    if(ret > 0) {
      /*Packet has arrived, Read it*/
      if(FD_ISSET(pNetCtx->raw_fd, &rd)) {
        memset((void *)&pNetCtx->packet, 0, sizeof(pNetCtx->packet));
        ret = read_eth_frame(pNetCtx->raw_fd, 
                             (unsigned char *)pNetCtx->packet, 
                             &pNetCtx->packet_len);
        if(ret) {
          recv_cb(pNetCtx->raw_fd, pNetCtx->packet, pNetCtx->packet_len);
        }

      } else if(FD_ISSET(pNetCtx->raw_fd, &pNetCtx->timer_fd)) {
        /*Invoke API for time out*/
        pNetCtx->callback(pNetCtx->callback_ctx);
        /*Clear timer fd set*/
        FD_CLR(pNetCtx->raw_fd, &pNetCtx->timer_fd);
      } 
    } else if(ret < 0) {
      fprintf(stderr, "\nError has happened %d\n", ret);
      perror("select:");
    }
  }

}/*net_main*/
#endif
