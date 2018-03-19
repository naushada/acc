#ifndef __OAUTH20_H__
#define __OAUTH20_H__


/*For WebApp*/
#define CLIENT_ID  "412727589579-uln740n6b2pqonc56n71lmc098aq7kqd.apps.googleusercontent.com"
#define CLIENT_S   "tl3aWxCgjo5YUOwZ_dPEKcJ6"

#if 0
/*For SERVER*/
#define CLIENT_ID "412727589579-75hubtl01bv2q89s7c6gsr5g3ad8gj7a.apps.googleusercontent.com"
#define CLIENT_S  "q79o9K-q1gpuGa8z8ZFkbtch"
#endif

typedef struct {
  /*google host name- www.accounts.google.com*/
  uint8_t host_name[64];
  /*random number encoded in base64 form*/
  uint8_t state[64];
  /*scope could be profile, email or openid*/
  uint8_t scope[16];
  /*once user is logged in, google will redirect user to this url*/
  uint8_t redirect_uri[128];
  /*listen ip*/
  uint32_t nas_ip;
  /*listen port*/
  uint16_t nas_port;
  /*nas_fd*/
  int32_t  nas_fd;

}oauth20_ctx_t;


int32_t oauth20_recv(int32_t fd, 
                     uint8_t *req_ptr, 
                     uint32_t req_ptr_size, 
                     uint32_t *req_ptr_len);

int32_t oauth20_send(int32_t fd, 
                     uint8_t *rsp_ptr, 
                     uint32_t rsp_ptr_len);

int32_t oauth20_init(uint8_t *host_name,
                     uint32_t nas_ip,
                     uint16_t nas_port);

void *oauth20_main(void *tid);

int32_t oauth20_process_nas_req(int32_t conn_id, 
                                uint8_t *req_ptr, 
                                uint32_t req_len);

int32_t oauth20_compute_state(uint8_t *b64, 
                              uint32_t *b64_len);

uint8_t *oauth20_get_param(uint8_t *packet_ptr, 
                           uint8_t *p_name);

int32_t oauth20_build_access_code_rsp(uint8_t *req_ptr, 
                                      uint8_t *rsp_ptr,
                                      uint32_t rsp_size, 
                                      uint32_t *rsp_len);

int32_t oauth20_build_access_token_req(uint8_t *req_ptr, 
                                       uint8_t *rsp_ptr, 
                                       uint32_t rsp_size, 
                                       uint32_t *rsp_len);

#endif /* __OAUTH20_H__ */
