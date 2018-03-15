#ifndef __OAUTH20_C__
#define __OAUTH20_C__

#include <type.h>
#include <uidai/common.h>
#include <uidai/util.h>
#include "oauth20.h"

oauth20_ctx_t oauth20_ctx_g;

int32_t oauth20_compute_state(uint8_t *b64, 
                              uint32_t *b64_len) {
  int32_t fd;
  uint8_t st[32];
  int32_t ret = -1;

  memset((void *)st, 0, sizeof(st));
  fd = open("/dev/urandom", O_RDONLY);
  if(fd < 0) {
    fprintf(stderr, "\n%s:%d opening of device file failed\n", __FILE__, __LINE__);
    return(1);
  }

  ret = read(fd, st, sizeof(st));
  if(ret <= 0) {
    fprintf(stderr, "\n%s:%d reading of device file failed\n", __FILE__, __LINE__);
    return(2);
  }  

  close(fd);
  util_base64(st, (uint16_t)ret, b64, (uint16_t *)b64_len);
   
  return(0);
}/*oauth20_compute_state*/

int32_t oauth20_build_auth_rsp(uint8_t *req_ptr, 
                               uint8_t *rsp_ptr,
                               uint32_t rsp_size, 
                               uint32_t *rsp_len) {
  uint8_t b64[64];
  uint32_t b64_len = 0;
  uint8_t *redirect_ptr = "http://adam.balaagh.com:8080/oauth2callback";
  /*value of scope would be - email, profile and openid, 
    more than one value shall be space seperated
   */
  uint8_t *scope_ptr = "email";
  uint8_t *response_type_ptr = "code";
  /*reference : https://developers.google.com/identity/protocols/OAuth2WebServer*/
  uint8_t *url_ptr = "https://accounts.google.com/o/oauth2/v2/auth";
  uint8_t *acc_type_ptr = "online";
  /*Optional. A space-delimited, case-sensitive list of prompts to present the user. 
    If you don't specify this parameter, the user will be prompted only the first time your app requests access. 
    Possible values are: 
    none, consent, select_account
   */
  uint8_t *prompt_ptr = "consent";
  uint8_t *conn_ptr = NULL;
  uint8_t *ext_conn_ptr = NULL;

  conn_ptr = oauth20_get_param(req_ptr, "conn_id");
  ext_conn_ptr = oauth20_get_param(req_ptr, "ext_conn_id");
  
  if(!conn_ptr || !ext_conn_ptr) {
    fprintf(stderr, "\n%s:%d conn_id or ext_conn_id is meiising\n", __FILE__, __LINE__);
    return(1);
  }
  
  memset((void *)b64, 0, sizeof(b64));
  oauth20_compute_state(b64, &b64_len);
  /*https://accounts.google.com/o/oauth2/v2/auth?
    scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.metadata.readonly&
    access_type=offline&
    include_granted_scopes=true&
    state=state_parameter_passthrough_value&
    redirect_uri=http%3A%2F%2Foauth2.example.com%2Fcallback&
    response_type=code&
    client_id=client_id
  */
  *rsp_len = snprintf(rsp_ptr,
                      rsp_size,
                      "%s%s%s%s%s"
                      "%s%s%s%s%s"
                      "%s%s%s%s%s"
                      "%s%s%s",
                      "/response?type=auth&subtype=redirect&uri=",
                      url_ptr,
                      "&scope=",
                      scope_ptr,
                      "&access_type=",
                      acc_type_ptr,
                      "&state=",
                      /*state is b64 encoded*/
                      b64,
                      "&redirect_uri=",
                      redirect_ptr,
                      "&response_type=",
                      response_type_ptr,
                      "&client_id=",
                      CLIENT_ID,
                      "&ext_conn_id=",
                      ext_conn_ptr,
                      "&conn_id=",
                      conn_ptr);

  fprintf(stderr, "\n%s:%d RESPONSE %s\n", __FILE__, __LINE__, rsp_ptr);
  free(conn_ptr);
  free(ext_conn_ptr);
  return(0);
}/*oauth20_build_auth_rsp*/

uint8_t *oauth20_get_param(uint8_t *packet_ptr, uint8_t *p_name) {

  uint8_t *param_value = NULL;
  uint32_t param_max_size = 512; 
  uint8_t *tmp_ptr = NULL;
  uint8_t *line_ptr = NULL;
  uint8_t param_name[32];
  uint8_t is_found = 0; 

  param_value = (uint8_t *)malloc(param_max_size);
  assert(param_value != NULL);
  tmp_ptr = (uint8_t *)malloc(strlen(packet_ptr));
  assert(tmp_ptr != NULL);
  memset((void *)tmp_ptr, 0, strlen(packet_ptr));
  sscanf(packet_ptr, "%*[^?]?%s", tmp_ptr);  

  line_ptr = strtok(tmp_ptr, "&");
  while(line_ptr) {
    memset((void *)param_name, 0, sizeof(param_name));
    memset((void *)param_value, 0, param_max_size);
    sscanf(line_ptr, "%[^=]=%s", param_name, param_value);

    if(!strncmp(param_name, p_name, strlen(p_name))) {
      is_found = 1; 
      break;  
    }    

    line_ptr = strtok(NULL, "&");
  }

  if(is_found) {
    free(tmp_ptr);
    return(param_value);
  }

  free(tmp_ptr);
  free(param_value);
  return(NULL);
}/*oauth20_get_param*/

int32_t oauth20_process_nas_req(int32_t conn_id, 
                                uint8_t *req_ptr, 
                                uint32_t req_len) {

  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_len = 0;
  uint32_t rsp_size = 1024;
  uint8_t *type_ptr = NULL;

  /*/request?type=auth&ext_conn_id=<>&conn_id=*/
  type_ptr = oauth20_get_param(req_ptr, "type");

  if(!type_ptr) {
    fprintf(stderr, "\n%s:%d type not found\n", __FILE__, __LINE__);
    return(1);
  }
  fprintf(stderr, "\n%s:%d type %s\n", __FILE__, __LINE__, type_ptr);

  if(!strncmp(type_ptr, "auth", 4)) {
    fprintf(stderr, "\n%s:%d type %s\n", __FILE__, __LINE__, type_ptr);
    /*Prepare the response for nas*/
    rsp_ptr = (uint8_t *) malloc(sizeof(uint8_t) * rsp_size);
    assert(rsp_ptr != NULL);
    memset((void *)rsp_ptr, 0, (sizeof(uint8_t) * rsp_size)); 
    oauth20_build_auth_rsp(req_ptr, rsp_ptr, rsp_size, &rsp_len);
  }
 
  if(rsp_len) {
    oauth20_send(conn_id, rsp_ptr, rsp_len);
  }

  free(type_ptr);
  free(rsp_ptr);

  return(0);
}/*oauth20_process_nas_req*/

int32_t oauth20_recv(int32_t fd, 
                     uint8_t *req_ptr, 
                     uint32_t req_ptr_size, 
                     uint32_t *req_ptr_len) {
  int32_t ret = -1;

  ret = recv(fd, req_ptr, req_ptr_size, 0);

  if(ret > 0) {
    *req_ptr_len = (uint32_t)ret;
  } else {
    *req_ptr_len = 0;
  }

  return(ret);
}/*oauth20_recv*/

int32_t oauth20_send(int32_t fd, 
                     uint8_t *rsp_ptr, 
                     uint32_t rsp_ptr_len) {
  uint32_t offset = 0;
  int32_t ret = -1;

  do {
    ret = send(fd, (rsp_ptr + offset), (rsp_ptr_len - offset), 0);

    if(ret > 0) {
      offset += ret;
    }
   
  }while((ret - offset));

  return(0);
}/*oauth20_send*/

int32_t oauth20_init(uint8_t *host_name,
                     uint32_t nas_ip,
                     uint16_t nas_port) {

  oauth20_ctx_t *pOauth20Ctx = &oauth20_ctx_g;
  const SSL_METHOD *method;
  int32_t fd;
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

  memset((void *)pOauth20Ctx->host_name, 0, sizeof(pOauth20Ctx->host_name));
  strncpy(pOauth20Ctx->host_name, host_name, strlen(host_name));

  memset((void *)pOauth20Ctx->state, 0, sizeof(pOauth20Ctx->state));
  memset((void *)pOauth20Ctx->scope, 0, sizeof(pOauth20Ctx->scope));
  memset((void *)pOauth20Ctx->redirect_uri, 0, sizeof(pOauth20Ctx->redirect_uri));

  pOauth20Ctx->nas_ip = nas_ip;
  pOauth20Ctx->nas_port = nas_port;

  /*Creating fd for nas request*/  
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation failed\n", __FILE__, __LINE__);
    return(1);
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(nas_ip);
  addr.sin_port = htons(nas_port);
  memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

  if(bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
    fprintf(stderr, "\n%s:%d Bind to given socket failed\n", __FILE__, __LINE__);
    return(2);
  }

  /*making socket to listen*/
  listen(fd, 5);
  pOauth20Ctx->nas_fd = fd;
  pOauth20Ctx->google_fd = -1;

  return(0);
}/*oauth20_init*/

void *oauth20_main(void *tid) {

  int32_t max_fd = 0;
  fd_set rd;
  struct timeval to;
  int32_t ret = 0;
  int32_t new_fd = -1;
  oauth20_ctx_t *pOauth20Ctx = &oauth20_ctx_g;

  FD_ZERO(&rd);

  for(;;) {
    to.tv_sec = 2;
    to.tv_usec = 0;
    FD_SET(pOauth20Ctx->nas_fd, &rd);
    max_fd = max_fd > pOauth20Ctx->nas_fd ? max_fd : pOauth20Ctx->nas_fd;
    
    if(pOauth20Ctx->google_fd > 0) {
      FD_SET(pOauth20Ctx->google_fd, &rd);
      max_fd = max_fd > pOauth20Ctx->google_fd ? max_fd : pOauth20Ctx->google_fd;
    }

    if(new_fd > 0) {
      FD_SET(new_fd, &rd);
      max_fd = max_fd > new_fd ? max_fd : new_fd;
    }

    max_fd = max_fd + 1;
    ret = select(max_fd, &rd, NULL, NULL, &to);

    if(ret < 0) {
      fprintf(stderr, "\n%s:%d error in select\n", __FILE__, __LINE__);
      continue;
    }

    if(FD_ISSET(pOauth20Ctx->nas_fd, &rd)) {
      /*new connection from nas*/
      struct sockaddr_in addr;
      socklen_t addr_len = sizeof(addr);
      new_fd = accept(pOauth20Ctx->nas_fd, (struct sockaddr *)&addr, &addr_len);
    }

    if((pOauth20Ctx->google_fd > 0) && (FD_ISSET(pOauth20Ctx->google_fd, &rd))) {
      /*Process response from google oauth20 server*/
      uint8_t rsp_buffer[512];
      uint32_t rsp_len = 0;
      memset((void *)rsp_buffer, 0, sizeof(rsp_buffer));
       
    }

    if((new_fd > 0) && (FD_ISSET(new_fd, &rd))) {
      /*Process Request from nas*/
      uint8_t req_buffer[512];
      uint32_t req_len = 0;
      memset((void *)req_buffer, 0, sizeof(req_buffer));
      oauth20_recv(new_fd, req_buffer, sizeof(req_buffer), &req_len);

      if(!req_len) {
        /*connection is closed*/
        close(new_fd);
        new_fd = -1;
      } else {
        oauth20_process_nas_req(new_fd, req_buffer, req_len);
      }
    }
  }

  return(0);
}/*oauth20_main*/


#endif /* __OAUTH20_C__ */
