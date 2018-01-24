#ifndef __REDIR_H__
#define __REDIR_H__

struct redir_session_t {
  
  uint32_t conn;
  struct sockaddr_in peer_addr;
  uint8_t method[8];
  uint8_t protocol[8];
  uint8_t uri[255];
  uint16_t mime_header_count;
  uint8_t mime_header[16][2][255];
  struct redir_session_t *next;

};

typedef struct redir_session_t redir_session_t;

typedef struct {
  uint32_t redir_listen_ip;
  uint16_t redir_listen_port;
  uint32_t uam_ip;
  uint16_t uam_port;
  int32_t redir_fd;
  /*Holds the Name of connection Status Table*/
  uint8_t conn_auth_status_table[128];
  /*Holds the ip allocation status*/
  uint8_t ip_allocation_table[128];

  redir_session_t *session;

}redir_ctx_t;


int32_t redir_recv(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint16_t *packet_length);

int32_t redir_send(int32_t fd, 
                   uint8_t *packet_ptr, 
                   uint16_t packet_length);

void redir_swap(uint32_t *a, 
                uint32_t *b);

uint32_t redir_partition(redir_session_t *session, 
                         int16_t low, 
                         int16_t high);

void redir_quick_sort(redir_session_t *arr, 
                      int16_t low_idx, 
                      int16_t high_idx);

void redir_modify_conn_count(redir_session_t *conn);

int32_t redir_process_req(uint32_t con_fd, 
                          uint8_t *packet_ptr, 
                          uint16_t packet_length);

redir_session_t *redir_get_session(uint32_t conn_id);

int32_t redir_init(uint32_t redir_listen_ip, 
                   uint16_t redir_listen_port, 
                   uint32_t uam_ip, 
                   uint16_t uam_port,
                   uint8_t *conn_status_table,
                   uint8_t *ip_allocation_table);

void *redir_main(void *argv);

#endif /* __REDIR_H__ */
