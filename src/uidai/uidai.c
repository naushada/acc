#ifndef __UIDAI_C__
#define __UIDAI_C__

#include <type.h>

#include "common.h"
#include "uidai.h"
#include "util.h"
#include "otp.h"
#include "auth.h"

uidai_ctx_t uidai_ctx_g;

uint8_t *uidai_get_param(uint8_t (*param)[2][64], 
                         const uint8_t *param_name) {

  uint32_t idx;

  for(idx = 0; param[idx][0]; idx++) {
    if(!strncmp(param[idx][0], param_name, strlen(param[idx][0]))) {
      return(param[idx][1]);
    }
  }

  return(NULL);
}/*uidai_get_param*/


int32_t uidai_build_ext_rsp(uint8_t (*param)[2][64], 
                            uint8_t **rsp_ptr, 
                            uint32_t *rsp_len) {
  uint8_t *txn;
  uint8_t rsp_type[50];

  memset((void *)rsp_type, 0, sizeof(rsp_type)); 
  txn = uidai_get_param(param, "txn");
  /*txn format will be <ext_conn_id>-<type>-<subtype>-XXXXXXX*/
  sscanf(txn, "%*[^-]-%s", rsp_type);

  if(!strncmp(rsp_type, "otp", 3)) {
    /*Build otp Response*/
    otp_process_rsp(param, rsp_ptr, rsp_len);
  } else if(!strncmp(rsp_type, "auth", 4)) {
    /*Build auth Response*/
    auth_process_rsp(param, rsp_ptr, rsp_len);
  }

  return(0);  
}/*uidai_build_ext_rsp*/

int32_t uidai_parse_uidai_rsp(int32_t conn_fd, 
                              const uint8_t *packet_ptr, 
                              uint32_t chunked_starts_at, 
                              uint32_t chunked_len,
                              uint8_t (*param)[2][64]) {

  uint8_t *chunked_ptr = NULL;
  uint8_t *tmp_ptr = NULL;
  uint8_t first_line[512];
  uint8_t *token_ptr = NULL;
  uint8_t attr_name[64];
  uint8_t attr_value[512];
  uint32_t idx = 0;

  memset((void *)first_line, 0, sizeof(first_line));

  chunked_ptr = (uint8_t *)malloc(chunked_len);
  assert(chunked_ptr != NULL);

  memset((void *)chunked_ptr, 0, chunked_len);
  sscanf((const char *)&packet_ptr[chunked_starts_at], "%*[^\n]\r\n%[^\n]", chunked_ptr);

  /*The delimeter is space*/
  tmp_ptr = chunked_ptr;
  token_ptr = strtok(tmp_ptr, " ");
  /*Start of the response*/
  while((token_ptr = strtok(NULL, " "))) {
    memset((void *)attr_name, 0, sizeof(attr_name));
    memset((void *)attr_value, 0, sizeof(attr_value));
    sscanf(token_ptr, "%[^=]=", attr_name);

    if(!strncmp(attr_name, "info", 4)) {
      break;
    }

    memset((void *)attr_name, 0, sizeof(attr_name));
    sscanf((const char *)token_ptr, "%[^=]=%s", attr_name, attr_value);

    strncpy((char *)param[idx][0], attr_name, strlen((const char *)attr_name));
    strncpy((char *)param[idx][1], attr_value, strlen((const char *)attr_value));
    idx++; 
  }

  param[idx][0][0] = '\0';
  param[idx][1][0] = '\0';
  free(chunked_ptr);

  return(0);
}/*uidai_parse_uidai_rsp*/

/**
 * @brief This function processes the response recived and 
 *  parses the received parameters. 
 *
 * @param conn_fd is the connection at which response is received.
 * @param packet_buffer holds the response buffer
 * @param packet_len is the received response length
 *
 * @return it returns 0 upon success else < 0 
 */
int32_t uidai_process_uidai_rsp(int32_t conn_fd, 
                                uint8_t *packet_ptr, 
                                uint16_t packet_len, 
                                uint8_t **rsp_ptr,
                                uint32_t *rsp_len) {

  uint8_t *tmp_ptr = packet_ptr;
  uint8_t *line_ptr = NULL;
  /*response body starts at*/
  uint16_t offset = 0;
  uint8_t is_response_chunked = 0;
  uint16_t chunked_len = 0;
  uint8_t hex_str[8];
  uint8_t param[16][2][64];
  uint16_t param_count;
  uint8_t status[8];
  uint32_t status_code;
  uint8_t proto[12];
  

  /*Parse the Response*/
  line_ptr = strtok(tmp_ptr, "\n");
  /*Extract the status code & status string*/
  memset((void *)status, 0, sizeof(status));
  memset((void *)proto, 0, sizeof(proto));
  status_code = 0;
  /*HTTP/1.1 200 OK*/
  sscanf(line_ptr, "%s%d%s",proto, (int32_t *)&status_code, status);
  /*Request was success*/
  if((!strncmp(status, "OK", 2)) && (200 == status_code)) {

    while(line_ptr) {

      /*+1 because of \r in each line*/
      offset += strlen((const char *)line_ptr) + 1;
      if(!strncmp(line_ptr, "\r",1)) {
        offset += 1;
        line_ptr = strtok(NULL, "\n");
        offset += strlen((const char *)line_ptr);
        break;

      } else if(!strncmp(line_ptr, "Transfer-Encoding: chunked", 26)) {
        /*Response received in chunked*/
        is_response_chunked = 1;

      } else if(!strncmp(line_ptr, "Content-Length:", 15)) {
        /*Response is not chunked*/
        fprintf(stderr, "\nResponse is non-chunked\n");
        is_response_chunked = 0;
        sscanf(line_ptr, "Content-Length: %d", (int32_t *)&chunked_len);
      }

      /*flushing the previous contents*/
      line_ptr = NULL;
      line_ptr = strtok(NULL, "\n");
    }

    if(is_response_chunked) {
      uint8_t rsp_type[16];
      /*Get the chunked length*/
      memset((void *)hex_str, 0, sizeof(hex_str));
      snprintf(hex_str, sizeof(hex_str), "0x%s", line_ptr);
      sscanf((const char *)hex_str, "%x", (int32_t *)&chunked_len);

      /*Copy the first chunked length*/
      memset((void *)param, 0, sizeof(param));
      memset((void *)rsp_type, 0, sizeof(rsp_type));
      uidai_parse_uidai_rsp(conn_fd, 
                            packet_ptr, 
                            offset, 
                            chunked_len, 
                            param);

      for(offset = 0; param[offset][0][0]; offset++) {
        fprintf(stderr, "\nname %s value %s\n", param[offset][0], param[offset][1]);
      }

      /*Prepare Response*/
      uidai_build_ext_rsp(param, rsp_ptr, rsp_len);
    }
  }

  return(0);
}/*uidai_process_uidai_rsp*/

int32_t uidai_add_session(uidai_session_t **head, uint32_t conn_fd) {
  uidai_session_t *curr = *head;
  uidai_session_t *new = (uidai_session_t *)malloc(sizeof(uidai_session_t));

  assert(new != NULL);
  new->ext_conn = conn_fd;
  new->next = NULL;

  if(!curr) {
    (*head) = new;
    return(0);
  }

  while(curr->next) {
    curr = curr->next;
  }

  curr->next = new;

  return(0);
}/*uidai_add_session*/

uidai_session_t *uidai_get_session(uidai_session_t *session, uint32_t conn_id) {

  if(session && (conn_id == session->ext_conn)) {
    return(session);

  } else if(!session) {
    return(NULL);

  } else {
    return(uidai_get_session(session->next, conn_id));

  }
}/*uidai_get_session*/

int32_t uidai_set_fd(uidai_session_t *session, fd_set *rd) {

  while(session) {
    FD_SET(session->ext_conn, rd);
    session = session->next;
  }

  return(0);
}/*uidai_set_fd*/

uint32_t uidai_get_max_fd(uidai_session_t *session) {
  uint32_t max_fd = 0;

  while(session) {
    max_fd = (max_fd > session->ext_conn) ? max_fd: session->ext_conn;
    session = session->next;
  }

  return(max_fd);
}/*uidai_get_max_fd*/

/**
 * @brief This function removes the matched node from the linked list if
 *        Elements are repeated.
 */
int32_t uidai_remove_session(uint32_t conn_id) {
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;
  uidai_session_t *prev = NULL;
  uidai_session_t *curr = pUidaiCtx->session;
  uidai_session_t *next = NULL;

  if(!curr) {
    /*The list is empty, nothing to be removed*/
    return(0);
  }

  /*Element to be deleted at begining*/
  if(curr && !curr->next) {
    /*only one node*/
    if(conn_id == curr->ext_conn) {
      /*Delete the head*/
      free(pUidaiCtx->session);
      pUidaiCtx->session = NULL;
    }
  }

  /*Element to be deleted in middle*/
  while(curr && curr->next) {
    if(conn_id == curr->ext_conn) {
      /*Got the conn_id and it is to be removed*/
      prev->next = curr->next;
      free(curr);
    }
    prev = curr;
    curr = curr->next;
  }
  
  /*element is found at last node*/
  if(!curr->next) {
    if(conn_id == curr->ext_conn) {
      prev->next = NULL;
      free(curr);
    } 
   
  }

  return(0);
}/*redir_remove_session*/

/**
 * @brief This function processes the response buffer
 *  without consuming the buffer and ensures that
 *  the complete response is received. It makes sure
 *  that incase of chunked response, end chunked is
 *  received.
 *
 * @param conn_fd is the connection at which response is received.
 * @param packet_buffer holds the response buffer
 * @param packet_len is the received response length
 *
 * @return it returns 0 if entire response is received else returns 1
 */
int32_t uidai_pre_process_uidai_rsp(int32_t conn_fd, 
                                    uint8_t *packet_ptr, 
                                    uint32_t packet_len) {
  uint8_t *tmp_ptr = packet_ptr;
  uint8_t *line_ptr = NULL;
  uint8_t is_response_chunked = 0;
  uint16_t payload_len = 0;
  uint8_t is_start_chunked = 0;
  uint8_t is_end_chunked = 0;
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;

  if(!packet_len) {
    /*connection has been closed*/
    pUidaiCtx->uidai_fd = -1;
    return(0);
  }

  /*Parse the Response*/
  line_ptr = strtok(tmp_ptr, "\n");
  while(line_ptr != NULL) {

    if(!strncmp(line_ptr, "\r",1)) {
      line_ptr = strtok(NULL, "\n");

      if(line_ptr) {
        is_start_chunked = 1;

      } else if(is_start_chunked && !line_ptr) {
        /*end chunked length will be ZERO*/
        is_end_chunked = 1;
      }

    } else if(!strncmp(line_ptr, "Transfer-Encoding: chunked", 26)) {
      /*Response received in chunked*/
      is_response_chunked = 1;

    } else if(!strncmp(line_ptr, "Content-Length:", 15)) {
      /*Response is not chunked*/
      fprintf(stderr, "\nResponse is non-chunked\n");
      is_response_chunked = 0;
      sscanf(line_ptr, "Content-Length: %d", (int32_t *)&payload_len);
    }

    line_ptr = NULL;
    line_ptr = strtok(NULL, "\n");
  }

  if(is_response_chunked && is_end_chunked) {
    /*Complete chuncked received*/
    return(0);
  }

  /*wait for end of chunked*/
  return(1);
}/*uidai_pre_process_uidai_rsp*/


int32_t uidai_process_req(int32_t conn_fd, 
                          uint8_t *packet_ptr, 
                          uint32_t packet_len) {
  uint8_t req_type[64];
  uint8_t *rsp_ptr = NULL;
  uint32_t rsp_len = 0;
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;

  fprintf(stderr, "\n%s:%d Request Received %s\n", __FILE__, __LINE__, packet_ptr);
  sscanf((const char *)packet_ptr, 
         "%*[^?]?type=%[^&]&", 
         req_type);

  if(!strncmp(req_type, "otp", 3)) {
    otp_main(conn_fd, packet_ptr, packet_len, &rsp_ptr, &rsp_len);

  } else if(!strncmp(req_type, "auth", 4)) {
    /*Process Auth Request*/
    auth_main(conn_fd, packet_ptr, packet_len, &rsp_ptr, &rsp_len);

  } else {
    /*Request Type is not supported*/
    fprintf(stderr, "\nIncorrect Request Type\n");
  }

  if(rsp_len) {
    if(pUidaiCtx->uidai_fd < 0) {
      /*Connect to uidai server*/
      uidai_connect_uidai();
    }

    fprintf(stderr, "\n%s:%d xml Request is \n%s", __FILE__, __LINE__, rsp_ptr);
    uidai_send(pUidaiCtx->uidai_fd, rsp_ptr, rsp_len);
    free(rsp_ptr);
    rsp_ptr = NULL;
  }

  return(0);
}/*uidai_process_req*/


int32_t uidai_recv(int32_t conn_fd, 
                   uint8_t *packet_ptr, 
                   uint32_t *packet_len,
                   int32_t flags) {
  int32_t ret = -1;

  if(!packet_ptr) {
    *packet_len = 0;
  }

  ret = recv(conn_fd, packet_ptr, *packet_len, flags);

  if(ret > 0) {
    *packet_len = (uint16_t)ret;
  } else if(ret <= 0) {
    *packet_len = 0;
  }

  return(0);
}/*uidai_recv*/

int32_t uidai_send(int32_t conn_fd, 
                   uint8_t *packet_ptr, 
                   uint32_t packet_len) {
  uint16_t offset = 0;
  int32_t ret = -1;

  do {
    ret = send(conn_fd, 
               (const void *)&packet_ptr[offset], 
               (packet_len - offset), 
               0);
    
    if(ret > 0) {
      offset += ret;
      
      if(!(packet_len - offset)) {
        ret = 0;
      }

    } else {
      fprintf(stderr, "\n%s:%d send failed\n", __FILE__, __LINE__);
      perror("send Failed");
      break;
    }

  }while(ret);

  return(ret);
}/*uidai_send*/

int32_t uidai_connect_uidai(void) {
  struct hostent *he;
  struct in_addr **addr_list;
  int32_t i;
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;
  struct sockaddr_in uidai_addr;
  socklen_t addr_len;
  int32_t fd;
  int32_t ret = -1;
  uint8_t ip_str[32];
  uint8_t ip[4];

  memset((void *)ip_str, 0, sizeof(ip_str));
  if(!(he = gethostbyname(pUidaiCtx->uidai_host_name))) {
    /*get the host info*/
    fprintf(stderr, "gethostbyname is returning an error\n");
    return (-1);
  }

  addr_list = (struct in_addr **) he->h_addr_list;

  for(i = 0; addr_list[i] != NULL; i++) {
    strcpy(ip_str ,inet_ntoa(*addr_list[i]));
    fprintf(stderr, "\n%s:%d uidai ip address %s\n",
                     __FILE__,
                     __LINE__,
                     ip_str);
    break;
  }
  
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation failed\n",
                    __FILE__,
                    __LINE__);
    return(-2);
  }

  sscanf((const char *)ip_str, 
         "%d.%d.%d.%d", 
         (int32_t *)&ip[0],
         (int32_t *)&ip[1],
         (int32_t *)&ip[2],
         (int32_t *)&ip[3]);

  uidai_addr.sin_family = AF_INET;
  uidai_addr.sin_port = htons(pUidaiCtx->uidai_port);

  uidai_addr.sin_addr.s_addr = htonl((ip[0] << 24 | 
                                ip[1] << 16 | 
                                ip[2] <<  8 | 
                                ip[3]));

  fprintf(stderr, "\n%s:%d uidai ip address %s\n",
                   __FILE__,
                   __LINE__,
                   ip_str);

  memset((void *)uidai_addr.sin_zero, 0, sizeof(uidai_addr.sin_zero));
  addr_len = sizeof(uidai_addr);

  ret = connect(fd, (struct sockaddr *)&uidai_addr, addr_len);

  if(ret < 0) {
    fprintf(stderr, "\n%s:%d connection with uidai failed\n",
                    __FILE__,
                    __LINE__);
    return(-3);
  }

  pUidaiCtx->uidai_fd = fd;

  return (0);
}/*uidai_connect_uidai*/


int32_t uidai_init(uint32_t ip_addr, 
                   uint32_t port, 
                   uint8_t *uidai_host, 
                   uint32_t uidai_port,
                   uint8_t *ac,
                   uint8_t *sa,
                   uint8_t *lk,
                   uint8_t *public_fname,
                   uint8_t *private_fname) {
  int32_t fd;
  struct sockaddr_in addr;
  size_t addr_len = sizeof(addr);
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;
 
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d Creation of Socket failed\n", 
                    __FILE__, 
                    __LINE__);
    return(-1);
  }
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(ip_addr);

  memset((void *)addr.sin_zero, 0, sizeof(addr.sin_zero));
 
  if(bind(fd, (struct sockaddr *)&addr, addr_len)) {
    fprintf(stderr, "\n%s:%d bind failed\n", __FILE__, __LINE__);
    return(-2);
  }

  listen(fd, 5/*number of simultaneous connection*/);
  pUidaiCtx->fd = fd;
  pUidaiCtx->port = port;
  pUidaiCtx->ip = ip_addr;

  memset((void *)pUidaiCtx->uidai_host_name, 0, sizeof(pUidaiCtx->uidai_host_name));
  strncpy(pUidaiCtx->uidai_host_name, uidai_host, strlen(uidai_host));

  pUidaiCtx->uidai_port = uidai_port;
  pUidaiCtx->uidai_fd = -1;

  memset((void *)pUidaiCtx->public_fname, 0, sizeof(pUidaiCtx->public_fname));
  strncpy(pUidaiCtx->public_fname, public_fname, strlen(public_fname));

  memset((void *)pUidaiCtx->private_fname, 0, sizeof(pUidaiCtx->private_fname));
  strncpy(pUidaiCtx->private_fname, private_fname, strlen(private_fname));

  util_init(pUidaiCtx->public_fname,
            pUidaiCtx->private_fname);

  otp_init(ac, 
           sa, 
           lk, 
           "1.6", 
           "developer.uidai.gov.in");

  auth_init(ac, 
            sa, 
            lk, 
            pUidaiCtx->private_fname, 
            pUidaiCtx->public_fname, 
            "developer.uidai.gov.in");

  return(0);
}/*uidai_init*/

void *uidai_main(void *tid) {
  int32_t ret = -1;
  fd_set rd;
  int32_t max_fd = 0;
  struct timeval to;
  uint8_t buffer[1500];
  uidai_ctx_t *pUidaiCtx = &uidai_ctx_g;
  uint32_t buffer_len;
  int32_t connected_fd = -1;
  uint8_t wait_for_more_data = 0;
  struct sockaddr_in peer_addr;
  socklen_t addr_len = sizeof(peer_addr);
  uidai_session_t *session = NULL;

  FD_ZERO(&rd);

  for(;;) {
    to.tv_sec = 2;
    to.tv_usec = 0;

    uidai_remove_session((uint32_t)0);
    uidai_set_fd(pUidaiCtx->session, &rd);
    max_fd = uidai_get_max_fd(pUidaiCtx->session);

    /*listening fd for request from Access COntroller*/
    FD_SET(pUidaiCtx->fd, &rd);
    max_fd = max_fd > pUidaiCtx->fd ?max_fd: pUidaiCtx->fd;

    if(pUidaiCtx->uidai_fd > 0) {
      FD_SET(pUidaiCtx->uidai_fd, &rd);
      max_fd = max_fd > pUidaiCtx->uidai_fd? max_fd: pUidaiCtx->uidai_fd;
    }

    max_fd += 1;
    ret = select(max_fd, &rd, NULL, NULL, &to);

    if(ret > 0) {
      if(FD_ISSET(pUidaiCtx->fd, &rd)) {
        /*New Connection*/
        connected_fd = accept(pUidaiCtx->fd, 
                             (struct sockaddr *)&peer_addr, 
                             &addr_len);
        uidai_add_session(&pUidaiCtx->session, connected_fd);
      }

      for(session = pUidaiCtx->session; session; session = session->next) { 
        if((session->ext_conn > 0) && FD_ISSET(session->ext_conn, &rd)) {
          /*Request received from Access Controller /NAS*/
          memset((void *)buffer, 0, sizeof(buffer));
          buffer_len = sizeof(buffer);
          uidai_recv(session->ext_conn, buffer, &buffer_len, 0);

          if(buffer_len) {
            fprintf(stderr, "\n%s:%d received for uidai Server %s\n", __FILE__, __LINE__, buffer);
            uidai_process_req(session->ext_conn, buffer, buffer_len);
          } else {
            session->ext_conn = 0;
          }
        }
      } 

      if((pUidaiCtx->uidai_fd > 0) && (FD_ISSET(pUidaiCtx->uidai_fd, &rd))) { 
        /*Response UIDAI Server*/
        do {
          memset((void *)buffer, 0, sizeof(buffer));
          buffer_len = sizeof(buffer);
          uidai_recv(pUidaiCtx->uidai_fd, buffer, &buffer_len, MSG_PEEK);
          wait_for_more_data = uidai_pre_process_uidai_rsp(pUidaiCtx->uidai_fd, 
                                                           buffer, 
                                                           buffer_len);
        }while(wait_for_more_data);

        if(buffer_len) {
          uint8_t *rsp_ptr = NULL;
          uint32_t rsp_len = 0;

          memset((void *)buffer, 0, sizeof(buffer));
          buffer_len = sizeof(buffer);
          uidai_recv(pUidaiCtx->uidai_fd, 
                     buffer, 
                     &buffer_len, 
                     0);
          fprintf(stderr, "\n%s:%d Response from UIDAI is %s\n", __FILE__, __LINE__, buffer);
          uidai_process_uidai_rsp(pUidaiCtx->uidai_fd, 
                                  buffer, 
                                  buffer_len, 
                                  &rsp_ptr, 
                                  &rsp_len);

          if(rsp_len && pUidaiCtx->session->ext_conn) {
            fprintf(stderr, "\n%s:%d response sent to uam %s\n", __FILE__, __LINE__, rsp_ptr);
            uidai_send(pUidaiCtx->session->ext_conn, rsp_ptr, rsp_len);
            free(rsp_ptr);
          }

        } else if(!buffer_len) {
          /*connection has been closed*/
          close(pUidaiCtx->uidai_fd);
          pUidaiCtx->uidai_fd = -1;
          fprintf(stderr, "\n%s:%d Connection is being closed\n", __FILE__, __LINE__);
        }
        
      }
    }
  }

  return(0);
}/*uidai_main*/

#if 0
int32_t main(int32_t argc, char *argv[]) {

  uint8_t b64_skey[1024];
  uint16_t b64_skey_size = sizeof(b64_skey);
  uint8_t buffer[1500];
  uint16_t buffer_len;
  //uint8_t *ip_str = "172.20.10.7";
  uint8_t *ip_str = "192.168.1.3";
  uint8_t ip[4];
  uint32_t ip_addr;

  util_init(/*"uidai_auth_stage.cer"*/"tmp_cer", "Staging_Signature_PrivateKey.p12");

  sscanf(ip_str, "%d.%d.%d.%d", 
                 (int32_t *)&ip[0], 
                 (int32_t *)&ip[1], 
                 (int32_t *)&ip[2], 
                 (int32_t *)&ip[3]);

  ip_addr = ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3];

  otp_init("public",
           "public",
           "MEaMX8fkRa6PqsqK6wGMrEXcXFl_oXHA-YuknI2uf0gKgZ80HaZgG3A"
           /*"MG41KIrkk5moCkcO8w-2fc01-P7I5S-6X2-X7luVcDgZyOa2LXs3ELI"*/,
           "1.6",
           "developer.uidai.gov.in");

  auth_init("public",
           "public",
           "MEaMX8fkRa6PqsqK6wGMrEXcXFl_oXHA-YuknI2uf0gKgZ80HaZgG3A"
           /*"MG41KIrkk5moCkcO8w-2fc01-P7I5S-6X2-X7luVcDgZyOa2LXs3ELI"*/,
           "Staging_Signature_PrivateKey.p12",
           "uidai_auth_stage.cer",
           /*"auth.uidai.gov.in"*/
           "developer.uidai.gov.in");
  
  memset((void *)buffer, 0, sizeof(buffer));
  buffer_len = snprintf(buffer, 
                        sizeof(buffer),
                        "%s",
                        "/request?type=otp&uid=999999990019");
                        /*"/request?type=otp&uid=8639859710");*/

  //otp_process_nas_req(8, buffer, buffer_len);

  memset((void *)buffer, 0, sizeof(buffer));
  buffer_len = sizeof(buffer);
#if 0
  otp_recv(pOtpCtx->otp_fd, buffer, &buffer_len);

  if(buffer_len > 0) {
    fprintf(stderr, "\n%s:%d ==> %s\n",
                    __FILE__,
                    __LINE__,
                    buffer);
  }
#endif

}/*main*/

#endif

#endif /* __UIDAI_C__ */
