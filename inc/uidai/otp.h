#ifndef __OTP_H__
#define __OTP_H__

typedef struct {
  /*Transaction Id*/
  uint8_t txn[50];
  /*A 12 digits Aadhaar id*/
  uint8_t uid[16];
  /*A 10 bytes unique code for AUA*/
  uint8_t ac[16];
  /*A 10 bytes unique Sub AUA*/
  uint8_t sa[16];
  /*ASA license key*/
  uint8_t lk[64];
  /*"A" for Aadhaar, "M" for Mobile*/
  uint8_t type[4];
  /*channel 00 - send OTP via both SMS and Email
                 (this is the default)
    channel 01 - send OTP via SMS only
    channel 02 - send OTP via Email only
   */
  uint8_t ch;
  /*otp API version, It's 1.6 as of now*/
  uint8_t ver[4];
  /*host name in the form of URI*/
  uint8_t uidai_host_name[255];
  uint16_t uidai_port;

  /*TCP Connection B/W nas and otp task*/
  int32_t nas_fd;
  uint32_t nas_port;
  uint32_t nas_ip;
  uint32_t otp_fd;

  uint8_t private_key_file[128];
  uint8_t public_key_file[128];
  
}otp_ctx_t;

/** @brief This function is to build the OTP xml
 *
 *  @param *otp_xml is the pointer to unsigned char which will holds the 
 *          otp_xml
 *  @param otp_xml_size is the otp_xml buffer size, i.e. how big is this otp_xml
 *  @param *otp_xml_len is the output which will give the zise of opt_xml
 *
 *  @return It will return for success else < 0
 */
int32_t otp_compose_otp_xml(uint8_t *otp_xml, 
                            uint16_t otp_xml_max_size, 
                            uint16_t *otp_xml_len);


/** @brief
 */

int32_t otp_init(uint8_t *ac,
                 uint8_t *sa,
                 /*license key*/
                 uint8_t *lk,
                 uint8_t *private_key_file,
                 uint8_t *public_key_file,
                 uint32_t nas_ip,
                 uint16_t nas_port,
                 uint8_t *uidai_host_name);

int32_t otp_compute_rsa_signature(uint8_t *signed_info,
                                  uint16_t signed_info_len, 
                                  uint8_t **signature_value, 
                                  uint16_t *signature_len);

int32_t otp_compute_rsa_key_value(uint8_t **modulus, 
                                  uint16_t *modulus_len, 
                                  uint8_t **exponent, 
                                  uint16_t *exponent_len);

int32_t otp_build_c14n_signedinfo_tag(uint8_t *c14n,
                                      uint16_t c14n_max_size,
                                      uint16_t *c14n_len,
                                      uint8_t *sha1_digest);

int32_t otp_build_c14n_otp_tag(uint8_t *c14n, 
                               uint16_t c14n_max_size, 
                               uint16_t *c14n_len);

int32_t otp_sign_xml(uint8_t **signed_xml, 
                     uint16_t *signed_xml_len);

int32_t otp_compute_digest(uint8_t *otp_xml, 
                           uint16_t otp_xml_len, 
                           uint8_t *digest);

int32_t otp_compute_b64(uint8_t *sha1, 
                        uint16_t sha1_len, 
                        uint8_t *b64, 
                        uint16_t *b64_len);

int32_t otp_compose_final_xml(uint8_t *out_xml, 
                              uint32_t out_xml_max_size, 
                              uint16_t *out_xml_len,
                              uint8_t *digest_b64,
                              uint8_t *signature_b64,
                              uint8_t *modulus_b64,
                              uint8_t *exponent_b64);

int32_t otp_compute_utf8(uint8_t *xml_in, 
                         uint16_t xml_in_len, 
                         uint8_t *utf8_set_out, 
                         uint16_t *utf8_set_len);

int32_t otp_request_otp(uint8_t *signed_xml, uint16_t signed_xml_len);

int32_t otp_recv(int32_t conn_fd, 
                 uint8_t *packet_ptr, 
                 uint16_t *packet_len);

int32_t otp_send(int32_t conn_fd, 
                 uint8_t *packet_ptr, 
                 uint16_t packet_len);

int32_t otp_connect_uidai(uint8_t *host_name);

int32_t otp_process_otp_req(uint8_t *uid, int32_t conn_id);

int32_t otp_process_nas_req(int32_t conn_fd, uint8_t *packet_ptr, uint16_t packet_len);

void *otp_main(void *tid);

int32_t otp_process_uidai_rsp(int32_t conn_fd, 
                              uint8_t *packet_ptr, 
                              uint16_t packet_len);

#endif /* __OTP_H__ */
