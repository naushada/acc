#ifndef __RADIUSC_H__
#define __RADIUSC_H__

#include <uamS_radiusC_interface.h>

typedef struct {
  
  struct sockaddr_in peer_addr;
  uint32_t conn; 
}radiusC_session_t;

typedef struct {
  uint8_t id;
  uint16_t ext_conn_id;
  uint16_t conn_id;
}radiusC_conn_t;

typedef struct {

  /* radiusX where X shall be 
   * C (Radius Client) or S (Radius Server)
   */
  uint32_t radiusC_ip;
  uint32_t radiusC_port;
  struct sockaddr_in self_addr;
  /*Radius Server IP*/
  uint32_t radiusS_ip;
  /*From UAM to RadiusC*/
  uint32_t radiusC_TcpFd;
  /*From RadiusC to RadiusS*/
  uint32_t radiusC_UdpFd;

  uint8_t secret_code[255];

  uint16_t session_count;
  radiusC_session_t session[255];

  uint8_t subscriber_count;
  radiusC_conn_t subscriber_id[255];

}radiusC_ctx_t;

typedef struct {
  uint8_t type;
  uint8_t len;
  uint8_t value[1];
}radiusC_radiusS_attr_t;

typedef struct {
  uint8_t code;
  uint8_t id;
  uint16_t len;
  uint8_t authenticator[16];
}radiusC_radiusS_message_header_t;

typedef enum {
  USER_NAME = 1,
  USER_PASSWORD,
  CHAP_PASSWORD,
  NAS_IP_ADDRESS,
  /*Physical Port at which NAS is operating*/
  NAS_PORT,
  SERVICE_TYPE,
  VENDOR_SPECIFIC = 26,
  CALLING_STATION_ID = 31

}radiusC_attr_type_t;




int32_t radiusC_send(uint32_t conn_fd, 
                     uint8_t *packet_ptr, 
                     uint16_t packet_length);

int32_t radiusC_recv(uint32_t conn_fd, 
                     uint8_t *packet_ptr, 
                     uint16_t *packet_length);

int32_t radiusC_get_dest_port(uint8_t *packet_ptr);

int32_t radiusC_sendto(uint8_t *packet_ptr, uint16_t packet_length);

int32_t radiusC_process_access_accept(radiusC_uamS_access_accept_t *rsp_ptr,
                                      uint8_t *packet_ptr,
                                      uint16_t packet_length);

int32_t http_get_req_authenticator(uint8_t *authenticator_ptr);

int32_t radiusC_process_NAS_request(uint32_t conn_fd,
                                    uint8_t *packet_ptr, 
                                    uint16_t packet_length);

int32_t radiusC_parse_radiusS_response(uint32_t conn_id, 
                                       uint8_t *packet_ptr, 
                                       uint16_t packet_length);

void radiusC_swap(uint32_t *a, uint32_t *b);


uint32_t radiusC_partition (radiusC_session_t *session, 
                            int16_t low, 
                            int16_t high);

void radiusC_quick_sort(radiusC_session_t *session, 
                        int16_t low_idx, 
                        int16_t high_idx);

void radiusC_modify_conn_count(radiusC_session_t *session);

uint32_t radiusC_get_con_id(uint8_t offset);

int32_t radiusC_process_radiusS_response(uint32_t UdpFd);

int32_t radiusC_init(uint32_t radiusC_ip, 
                     uint32_t radiusC_port,
                     uint32_t radiusS_ip,
                     uint8_t *secret);

void *radiusC_main(void *arg);

int32_t radiusC_encode_password(uint8_t *password_ptr, 
                                uint16_t password_len,
                                uint8_t *authenticator_ptr,
                                uint8_t *encoded_password_ptr,
                                uint16_t *len_ptr);

#endif /* __RADIUSC_H__ */
