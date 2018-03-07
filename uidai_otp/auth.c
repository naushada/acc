#ifndef __AUTH_C__
#define __AUTH_C__

#include <common.h>
#include <uidai.h>
#include <util.h>
#include <auth.h>
#include <verify.h>

auth_ctx_t auth_ctx_g;

int32_t auth_process_rsp(uint8_t (*param)[2][64], 
                         uint8_t **rsp_ptr, 
                         uint32_t *rsp_len) {
  uint8_t *ret_ptr = NULL;
  uint8_t *txn_ptr = NULL;
  uint8_t *err_ptr = NULL;
  uint8_t ext_conn[8];
  uint8_t type[16];
  uint8_t subtype[16];
  uint8_t uid[14];
  uint8_t status[64];
  uint32_t rsp_size = 512;

  /*Initialize the auto variables*/
  memset((void *)ext_conn, 0, sizeof(ext_conn));
  memset((void *)type, 0, sizeof(type));
  memset((void *)subtype, 0, sizeof(subtype));
  memset((void *)uid, 0, sizeof(uid));

  ret_ptr = uidai_get_param(param, "ret");
  txn_ptr = uidai_get_param(param, "txn");
  /*extracting element from txn*/ 
  assert(txn_ptr != NULL);
  assert(ret_ptr != NULL);

  sscanf(txn_ptr, "%[^_]_%[^_]_%[^_]_%[^_]_",
                  ext_conn,
                  type,
                  subtype,
                  uid);
  memset((void *)status, 0, sizeof(status));
  if(!strncmp(ret_ptr, "y", 1)) {
    strncpy(status, "status=success", sizeof(status));
  } else {
    err_ptr = uidai_get_param(param, "err");
    assert(err_ptr != NULL);
    snprintf(status, 
             sizeof(status),
             "%s%s",
             "status=failed&reason=", 
             err_ptr);
  }

  /*Build final response*/
  *rsp_ptr = (uint8_t *)malloc(rsp_size);
  assert(*rsp_ptr != NULL);

  memset((void *)(*rsp_ptr), 0, rsp_size);
  /*/response?type=otp&uid=xxxxxxxxxxxx&ext_conn_id=dddd&status=success/failed&reason=err_code*/
  *rsp_len = snprintf((*rsp_ptr), 
                      rsp_size,
                      "%s%s%s%s%s"
                      "%s%s%s%s%s",
                      "/response?type=",
                      type,
                      "subtype=",
                      subtype,
                      "&uid=",
                      uid,
                      "&ext_conn_id=",
                      ext_conn,
                      "&",
                      status);
  
  return(0);
}/*auth_process_rsp*/

int32_t auth_to_char(uint8_t *in, 
                     uint32_t inl, 
                     uint8_t *out, 
                     uint32_t *outl) {
  uint32_t idx;
  
  for(idx = 0; idx < inl; idx++) {
    sprintf(out + idx, "%c", in[idx]);
    *outl += 1;
  }

  return(0);
}/*auth_to_char*/

int32_t auth_dump_xml(uint8_t *auth_xml, uint32_t auth_xml_len) {
  FILE *fp;

  fp = fopen("Auth_xml.xml", "w");

  if(fwrite(auth_xml, 1, auth_xml_len, fp) < auth_xml_len) {
    /*Writing to xml failed*/
    fclose(fp);
    return(-1);
  }  

  fclose(fp);
  return(0);
}/*auth_dump_xml*/

int32_t auth_symmetric_keys(uint8_t *out_ptr, uint32_t out_len) {
  FILE *fp = NULL;
  int32_t rc;
  FILE *oFp = NULL;

  fp = fopen("/dev/random", "rb");

  #if 0
  fp = fopen("skey_file", "rb");
  #endif

  if(!fp) {
    fprintf(stderr, "\n%s:%d opening of device file failed\n", __FILE__, __LINE__);
    return(-1);
  }

  rc = fread(out_ptr, 1, out_len, fp);
  fclose(fp);

  if(rc < out_len) {
    fprintf(stderr, "\n%s:%d shorter length than expected\n", __FILE__, __LINE__);
    return(-2);
  }

  for(rc = 0; rc < out_len; rc++) {
    fprintf(stderr, "%.2x ", out_ptr[rc]);
  }

#if 0
  oFp = fopen("skey_file", "wb");
  rc = fwrite(out_ptr, 1, out_len, oFp);
  fclose(oFp);
#endif
  return(0);
}/*auth_symmetric_keys*/

int32_t auth_compute_ts(uint8_t *ts, uint16_t ts_size) {

  FILE *fp = NULL;
  time_t curr_time;
  struct tm *local_time;
  auth_ctx_t *pAuthCtx = &auth_ctx_g;

  /*Retrieving the current time*/
  curr_time = time(NULL);
  local_time = localtime(&curr_time);

  memset((void *)ts, 0, ts_size);
  snprintf(ts, 
           ts_size,
           "%04d-%02d-%02dT%02d:%02d:%02d", 
           local_time->tm_year+1900, 
           local_time->tm_mon+1, 
           local_time->tm_mday, 
           local_time->tm_hour, 
           local_time->tm_min, 
           local_time->tm_sec);
#if 0
  fp = fopen("ts_file", "r");

  fread(ts, 1, ts_size, fp);
  fclose(fp);

#endif
  memset((void *)pAuthCtx->ts, 0, sizeof(pAuthCtx->ts));
  memset((void *)pAuthCtx->iv, 0, sizeof(pAuthCtx->iv));
  memset((void *)pAuthCtx->aad, 0, sizeof(pAuthCtx->aad));
  /*copying iv & aad into its context*/ 
  strncpy(pAuthCtx->iv, (const char *)&ts[strlen(ts) - 12], 12);
  strncpy(pAuthCtx->aad, (const char *)&ts[strlen(ts) - 16], 16);
  strncpy(pAuthCtx->ts, (const char *)ts, strlen(ts));

#if 0
  uint32_t tmp_len = 0;
  fprintf(stderr, "\nts %s\n", ts);

  for(tmp_len = 0; tmp_len < strlen(ts); tmp_len++) {
    fprintf(stderr, "(%.2X %d)", ts[tmp_len], ts[tmp_len]);
  }
  fprintf(stderr, "\n");
  tmp_len = 0;
  auth_to_char(&ts[strlen(ts) - 12], 12, pAuthCtx->iv, &tmp_len); 
  fprintf(stderr, "\niv_len %d\n", tmp_len);
  tmp_len = 0;
  auth_to_char(&ts[strlen(ts) - 16], 16, pAuthCtx->aad, &tmp_len); 
  fprintf(stderr, "\naad_len %d\n", tmp_len);
  tmp_len = 0;
  auth_to_char(ts, strlen(ts), pAuthCtx->ts, &tmp_len); 
  fprintf(stderr, "\nts_len %d ts %s aad %s\n", tmp_len, pAuthCtx->ts, pAuthCtx->aad);
#endif
  //fprintf(stderr, "\n%s:%d iv %s aad %s ts %s len(ts) %d\n", __FILE__, __LINE__, pAuthCtx->iv, pAuthCtx->aad, ts, strlen(ts)); 

#if 0
  uint8_t b64[64];
  uint8_t text[64];
  uint16_t b64_len;
  uint32_t text_len;
  memset((void *)b64, 0, sizeof(b64));
  util_base64(ts, strlen(ts), b64, &b64_len);
  memset((void*)text, 0, sizeof(text));
  util_base64_decode(b64, b64_len, text, &text_len);
#endif
  return(0);
}/*auth_compute_ts*/

int32_t auth_init(const uint8_t *ac,
                  const uint8_t *sa,
                  const uint8_t *lk,
                  const uint8_t *private_key,
                  const uint8_t *public_key,
                  const uint8_t *host_name) {

  auth_ctx_t *pAuthCtx = &auth_ctx_g;

  strncpy(pAuthCtx->ac, ac, strlen(ac)); 
  strncpy(pAuthCtx->sa, sa, strlen(sa)); 
  strncpy(pAuthCtx->lk, lk, strlen(lk)); 
  strncpy(pAuthCtx->private_key, private_key, strlen(private_key)); 
  strncpy(pAuthCtx->public_key, public_key, strlen(public_key));
  strncpy(pAuthCtx->version, "2.0", 3);
  strncpy(pAuthCtx->rc, "Y", 1);
  strncpy(pAuthCtx->uidai_host_name, host_name, strlen(host_name));
  strncpy(pAuthCtx->tid, "", 1);
  strncpy(pAuthCtx->txn, "DemoClient", 10);
  memset((void *)pAuthCtx->iv, 0, sizeof(pAuthCtx->iv));
  memset((void *)pAuthCtx->aad, 0, sizeof(pAuthCtx->aad));
   
  return(0);
}/*auth_init*/

int32_t auth_meta(uint8_t *meta, 
                  uint16_t meta_size, 
                  uint8_t *c14n, 
                  uint16_t c14n_size) {

  uint8_t *tmp_meta = "<Meta udc=\"SampleClientDemo\"";
  memset((void *)meta, 0, meta_size);

  snprintf(meta, 
           meta_size,
           "%s%s",
           tmp_meta,
           "/>");

  /*Canonicalization*/
  snprintf(c14n, 
           c14n_size,
           "%s%s",
           tmp_meta,
           "></Meta>");

  return(0);
}/*auth_meta*/

int32_t auth_pid_otp(uint8_t *pid_otp, 
                     uint16_t pid_otp_size, 
                     uint8_t *otp_value, 
                     uint8_t *ts) {

  auth_ctx_t *pAuthCtx = &auth_ctx_g;

  memset((void *)pid_otp, 0, pid_otp_size);

  snprintf(pid_otp,
           pid_otp_size,
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s",
           "<Pid xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request-data/",
           pAuthCtx->version,
           "\" ts=\"",
           ts,
           "\" ver=\"",
           pAuthCtx->version,
           "\" wadh=\"\">\n",
           "  <Pv otp=\"",
           otp_value,
           "\" pin=\"\"/>\n",
           "</Pid>");

  fprintf(stderr, "\n%s:%d PID \n%s\n", __FILE__, __LINE__, pid_otp);
  fprintf(stderr, "\n%s:%d iv %s aad %s\n", __FILE__, __LINE__, pAuthCtx->iv, pAuthCtx->aad);
  return(0);
}/*auth_pid_otp*/

int32_t auth_data(uint8_t *data, uint16_t data_size, uint8_t *pid_xml) {

  uint8_t ciphered_data[512];
  int32_t ciphered_data_len;
  uint8_t b64[512];
  uint16_t b64_len;
  uint8_t plain_txt[512];
  int32_t plain_txt_len;
  uint8_t tag[16];
  
  memset((void *)ciphered_data, 0, sizeof(ciphered_data)); 
  memset((void *)tag, 0, sizeof(tag));
  auth_cipher(pid_xml, 
              strlen(pid_xml), 
              ciphered_data, 
              &ciphered_data_len,
              tag);
#if 0
  auth_cipher_ex(pid_xml, 
                 (strlen(pid_xml) + 1), 
                 ciphered_data, 
                 &ciphered_data_len);
#endif

  fprintf(stderr, "\n%s:%d ciphered data len %d\n", __FILE__, __LINE__, ciphered_data_len);
  auth_decipher(ciphered_data, ciphered_data_len, plain_txt, &plain_txt_len, tag);

  fprintf(stderr, "\n%s:%d Plain txt \n%s len %d\n", __FILE__, __LINE__, plain_txt, plain_txt_len);

  memset((void *)b64, 0, sizeof(b64));
  util_base64(ciphered_data, ciphered_data_len, b64, &b64_len);

  memset((void *)data, 0, data_size);

  snprintf(data,
           data_size,
           "%s%s%s",
           "<Data type=\"X\">",
           b64,
           "</Data>");

  return(0);
}/*auth_data*/

int32_t auth_uses(uint8_t *uses_otp, 
                  uint16_t uses_otp_size, 
                  uint8_t *c14n, 
                  uint16_t c14n_size,
                  uint8_t *pid_uses_opt) {

  int32_t idx;
  uint8_t *loc = NULL;
  uint8_t uses_opt[256];
  uint8_t *tmp_uses = "<Uses bio=\"n\" bt=\"n\" otp=\"n\" pa=\"n\" pfa=\"n\" pi=\"n\" pin=\"n\"";
  memset((void *)uses_otp, 0, uses_otp_size);
  memset((void *)c14n, 0, c14n_size);

  loc = strstr(tmp_uses, pid_uses_opt);
  idx = loc ? (loc - tmp_uses) : -1;
  memset((void *)uses_opt, 0, sizeof(uses_opt));
  strncpy(uses_opt, tmp_uses, strlen(tmp_uses));

  if(idx > 0) {
    strncpy(&uses_opt[idx + strlen(pid_uses_opt) + 2], "y", 1);
  }

  snprintf(uses_otp, 
           uses_otp_size,
           "%s%s",
           uses_opt,
           "/>");

  /*Canonicalization*/
  snprintf(c14n, 
           c14n_size,
           "%s%s",
           uses_opt,
           "></Uses>");

  return(0);
}/*auth_uses*/

int32_t auth_decipher(uint8_t *ciphered_txt, 
                      int32_t ciphered_txt_len, 
                      uint8_t *plain_txt, 
                      int32_t *plain_txt_len,
                      uint8_t *tag) {
 
  int32_t tmp_len = 0;
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  EVP_CIPHER_CTX *x;

  x = EVP_CIPHER_CTX_new();

  if(!EVP_DecryptInit_ex(x, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-1);
  }

  EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);

  /* Now we can set key and IV */
  if(!EVP_DecryptInit_ex(x, NULL, NULL, pAuthCtx->session_key, pAuthCtx->iv)) {
    fprintf(stderr, "\n%s:%d Setting of keys and iv failed \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-2);
  }

  EVP_DecryptUpdate(x, NULL, &tmp_len, pAuthCtx->aad, 16);

  if(!EVP_DecryptUpdate(x, plain_txt, plain_txt_len, ciphered_txt, (ciphered_txt_len - (16 + 19)))) {
    /* Error */
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return 0;
  }

  EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, 16, tag);

  if(!EVP_DecryptFinal_ex(x, (plain_txt + *plain_txt_len), &tmp_len)) {
    /* Error */
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return 0;
  }

  *plain_txt_len += tmp_len;
  EVP_CIPHER_CTX_free(x);

  return(0); 
}/*auth_decipher*/

int auth_cipher_ex(uint8_t *data, 
                   uint16_t data_len, 
                   uint8_t *ciphered_data, 
                   int32_t *ciphered_data_len) {
  int32_t tmp_len = 0;
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  EVP_CIPHER_CTX *x;
  const EVP_CIPHER *cipher;

  x = EVP_CIPHER_CTX_new();
  cipher = EVP_get_cipherbyname("aes-256-ecb");
  //cipher = EVP_get_cipherbyname("aes-256-cbc");

  if(1 != EVP_EncryptInit_ex(x, cipher, NULL, pAuthCtx->session_key, NULL)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-1);
  }

  if(1 != EVP_CIPHER_CTX_set_padding(x, /*EVP_PADDING_PKCS7*/1)) {
    fprintf(stderr, "\n%s:%d Setting of PKCS7 Padding Failed\n",
                     __FILE__, __LINE__);
    return(-2);
  }

  //EVP_CIPHER_CTX_set_padding(x, 0);

  fprintf(stderr, "\ndata_len %d key_len %d iv_len %d \n", 
               data_len,
               EVP_CIPHER_CTX_key_length(x), 
               EVP_CIPHER_CTX_iv_length(x));

  /*key_length & iv_length is set based on EVP_aes_256_cbc type*/
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(x) == 32);
  /*128-bits of block*/
#if 0
  if(1 != EVP_EncryptInit_ex(x, NULL, NULL, pAuthCtx->session_key, NULL)) {
    fprintf(stderr, "\n%s:%d Setting of keys and iv failed \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-2);
  }
#endif
  //cipher = EVP_get_cipherbyname("aes-256-ecb");
  fprintf(stderr, "\n%s:%d nid %d block_size %d key_length %d iv_length %d flags %d mode %d, cipher_type %d\n",
                  __FILE__,
                  __LINE__,
                  EVP_CIPHER_nid(cipher),
                  EVP_CIPHER_block_size(cipher),
                  EVP_CIPHER_key_length(cipher),
                  EVP_CIPHER_iv_length(cipher),
                  EVP_CIPHER_flags(cipher),
                  EVP_CIPHER_mode(cipher),
                  EVP_CIPHER_type(cipher));
  if(EVP_CIPH_ECB_MODE == EVP_CIPHER_mode(cipher)) {
    fprintf(stderr, "\nCipher Mode is EVP_CIPH_ECB_MODE\n");
  }

  if(NID_undef == EVP_CIPHER_nid(cipher)) {
    fprintf(stderr, "\n NID is undef\n");
  }
  fprintf(stderr, "\nFrom CTX\n"); 
  fprintf(stderr, "\n%s:%d nid %d block_size %d key_length %d iv_length %d flags %d mode %d, cipher_type %d\n",
                  __FILE__,
                  __LINE__,
                  EVP_CIPHER_CTX_nid(x),
                  EVP_CIPHER_CTX_block_size(x),
                  EVP_CIPHER_CTX_key_length(x),
                  EVP_CIPHER_CTX_iv_length(x),
                  EVP_CIPHER_CTX_flags(x),
                  EVP_CIPHER_CTX_mode(x),
                  EVP_CIPHER_CTX_type(x));

  if(1 != EVP_EncryptUpdate(x, ciphered_data, ciphered_data_len, data, data_len)) {
    /* Error */
    EVP_CIPHER_CTX_free(x);
    return 0;
  }

  if(1 != EVP_EncryptFinal_ex(x, (ciphered_data + *ciphered_data_len), &tmp_len)) {
    /* Error */
    EVP_CIPHER_CTX_free(x);
    return 0;
  }

  *ciphered_data_len += tmp_len;
  EVP_CIPHER_CTX_cleanup(x);
  EVP_CIPHER_CTX_free(x);
  return(0); 

}/*auth_cipher_ex*/

/**
 * @brief This function is to cipher the plain text by using
 *        symmetric algorithm namley AES + ECB + PKCS7_PADDING
 *        Padding is required to make ciphered data into block of 16
 *        bytes i.e 128bits. For AES + ECB + PKCS7 Padding IV (Initialization
 *        Vector) is not required.
 * @param data is a pointer to character which holds the data to be encrypted
 * @param data_len is the length of plain data to be encrypted
 * @param ciphered_data which holds the encrypted data
 * @param ciphered_data_len which holds the length of ciphered data
 *
 * @return upon success it returns 0 else less than zero.
 */
int32_t auth_cipher(uint8_t *data, 
                    uint16_t data_len, 
                    uint8_t *ciphered_data, 
                    int32_t *ciphered_data_len, 
                    uint8_t *tag) {
 
  int32_t tmp_len = 0;
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  EVP_CIPHER_CTX *x;
  int32_t offset = 0;
  uint8_t ci_text[1024];
  
  memset((void *)ci_text, 0, sizeof(ci_text));

  x = EVP_CIPHER_CTX_new();

  if(!x) {
    fprintf(stderr, "\n%s:%d Instantiation of CIPHER CTX Failed\n",
                     __FILE__, __LINE__);
    return(-1);
  }
  //OpenSSL_add_all_ciphers();

  /*Initializing Encryption Engine*/
  if(1 != EVP_EncryptInit_ex(x, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-2);
  }

  if(1 != EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    /*Setting of iv Length failed*/
    EVP_CIPHER_CTX_free(x);
    return(-3);
  }

  /*Initializing symmetric key and iv*/
  if(1 != EVP_EncryptInit_ex(x, NULL, NULL, pAuthCtx->session_key, pAuthCtx->iv)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-4);
  }

  if(1 != EVP_EncryptUpdate(x, NULL, &tmp_len, pAuthCtx->aad, 16)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-5);
  }

  while(offset <= data_len - 16) {

    if(1 != EVP_EncryptUpdate(x, &ci_text[offset], &tmp_len, &data[offset], 16)) {
      /* Error */
      fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
      EVP_CIPHER_CTX_free(x);
      return(-6);
    }
    offset += tmp_len;
  }

  if(offset < data_len) {
    if(1 != EVP_EncryptUpdate(x, &ci_text[offset], &tmp_len, &data[offset], (data_len - offset))) {
      /* Error */
      fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
      EVP_CIPHER_CTX_free(x);
      return(-7);
    }
    offset += tmp_len;
  }

  if(1 != EVP_EncryptFinal_ex(x, &ci_text[offset], &tmp_len)) {
    /* Error */
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-7);
  }

  offset += tmp_len;
  /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
    fprintf(stderr, "\n%s:%d ERROR!! \n", __FILE__, __LINE__);
    EVP_CIPHER_CTX_free(x);
    return(-8);
  }

  memcpy((void *)&ci_text[offset], tag, 16); 
  offset += 16;
  
  uint8_t tmp_ts[32];
  uint32_t tmp_ts_len = 0;
  memset((void *)tmp_ts, 0, sizeof(tmp_ts));
  //auth_to_char(pAuthCtx->ts, strlen(pAuthCtx->ts), tmp_ts,&tmp_ts_len);

  //memcpy((void *)&ci_text[offset], pAuthCtx->ts, strlen(pAuthCtx->ts));
  memcpy((void *)&ci_text[offset], pAuthCtx->ts, 19);
  //memcpy((void *)&ci_text[offset], tmp_ts, tmp_ts_len);

  //offset += strlen(pAuthCtx->ts);
  offset += 19;

  memcpy((void *)ciphered_data, ci_text, offset);
  *ciphered_data_len = offset;

  EVP_CIPHER_CTX_cleanup(x);
  EVP_CIPHER_CTX_free(x);

  /*Data is encrypted successfully*/
  return(0); 
}/*auth_cipher*/

int32_t auth_hmac(uint8_t *hmac,
                  uint16_t hmac_size,
                  uint8_t *pid_xml) {

  uint8_t digest256[32];
  int32_t ciphered_data_len = 0;
  uint8_t ciphered_data[512];
  uint8_t b64_hmac[512];
  uint16_t b64_hmac_len;
  uint8_t tag[16];
  
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  EVP_CIPHER_CTX *x;
  SHA256_CTX ctx;

  memset((void *)digest256, 0, sizeof(digest256));

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, pid_xml, strlen((const char *)pid_xml));
  SHA256_Final(digest256, &ctx);

  memset((void *)tag, 0, sizeof(tag));
  memset((void *)ciphered_data, 0, sizeof(ciphered_data));
  auth_cipher(digest256, 32, ciphered_data, &ciphered_data_len, tag);

  //auth_cipher_ex(digest256, 32, ciphered_data, &ciphered_data_len);
  fprintf(stderr, "\n%s:%d ciphered data len HMAC %d\n", __FILE__, __LINE__, ciphered_data_len);
  memset((void *)b64_hmac, 0, sizeof(b64_hmac));
  util_base64(ciphered_data, ciphered_data_len, b64_hmac, &b64_hmac_len);
 
  memset((void *)hmac, 0, hmac_size);
  snprintf(hmac, 
           hmac_size, 
           "%s%s%s",
           "<Hmac>",
           b64_hmac,
           "</Hmac>");

  return(0);
}/*auth_hmac*/

int32_t auth_skey(uint8_t *b64_skey, uint16_t b64_skey_size) {

  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  FILE *fp = NULL;
  X509 *x509;
  RSA *rsa;
  EVP_PKEY *pkey;
  BIO *bio;
  ASN1_TIME *expiry_date;
  uint8_t not_after[256];
  size_t len = sizeof(not_after);
  uint8_t *ciphered_session_key;
  uint8_t b64_cipher[512];
  uint16_t b64_cipher_len;
  /*Length of encrypted session key*/
  int32_t cipher_len;
  uint8_t dd[4];
  uint8_t mm[4];
  uint8_t yyyy[8];
  uint8_t *tmp_ptr = NULL;
  uint16_t idx;
  int32_t rc;
  uint8_t *mm_str[] = {"Dummy", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", NULL};

  memset((void *)pAuthCtx->session_key, 0, sizeof(pAuthCtx->session_key));
  auth_symmetric_keys(pAuthCtx->session_key, sizeof(pAuthCtx->session_key));

  memset((void *)yyyy, 0, sizeof(yyyy));
  memset((void *)mm, 0, sizeof(mm));
  memset((void *)dd, 0, sizeof(dd));

  fp = fopen(pAuthCtx->public_key, "r");

  if(!fp) {
    fprintf(stderr, "\n%s:%d Opening of public key file failed\n", __FILE__, __LINE__);
    return(-1);
  }

  x509 = X509_new();
  PEM_read_X509(fp, &x509, NULL, NULL);

  if(!x509) {
    fprintf(stderr, "\n%s:%d Opening of certificate File failed\n", __FILE__, __LINE__);
    return(-2);
  }
  pkey = X509_get_pubkey(x509);

  /*Retrieve Certificate Expiry date*/
  expiry_date = X509_get_notAfter(x509);

  bio = BIO_new(BIO_s_mem());

  if(!bio) {
    fprintf(stderr, "\n%s:%d Instantiation of BIO failed\n", __FILE__, __LINE__);
    X509_free(x509);
    fclose(fp);
    return(-2);
  }

  if(!ASN1_TIME_print(bio, expiry_date)) {
    fprintf(stderr, "\n%s:%d expiry date for bio failed\n", __FILE__, __LINE__);
    BIO_free(bio);
    X509_free(x509);
    fclose(fp);
    return(-3);
  }

  if(!BIO_gets(bio, not_after, len)) {
    fprintf(stderr, "\n%s:%d retrieval of expiry date failed\n", __FILE__, __LINE__);
    BIO_free(bio);
    X509_free(x509);
    fclose(fp);
    return(-4);
  }

  fprintf(stderr, "\n%s:%d not after %s\n", __FILE__, __LINE__, not_after);
  tmp_ptr = strtok(not_after, " ");
  strncpy(mm, tmp_ptr, strlen((const char *)tmp_ptr));  
  tmp_ptr = strtok(NULL, " ");
  strncpy(dd, tmp_ptr, strlen((const char *)tmp_ptr));
  tmp_ptr = strtok(NULL, " ");
  tmp_ptr = strtok(NULL, " ");
  strncpy(yyyy, tmp_ptr, strlen((const char *)tmp_ptr));
 
  for(idx = 0; mm_str[idx]; idx++) {
    if(!strncmp(mm_str[idx], mm, strlen((const char *)mm))) {
      break;
    }
  }

  BIO_free(bio);
  memset((void *)not_after, 0, sizeof(not_after));

  snprintf(not_after, 
           sizeof(not_after),
           "%s%.2d%s",
           yyyy,
           idx,
           dd);

  fclose(fp);

  rsa = EVP_PKEY_get1_RSA(pkey);

  if(!rsa) {
    fprintf(stderr, "\n%s:%d the RSA is NULL\n", __FILE__, __LINE__);
    return(-3);
  }
#if 0
  fprintf(stderr, "\n%s:%d RSA_bits %d RSA_size %d RSA_flags %d\n", 
                  __FILE__, __LINE__,
                  RSA_bits(rsa), RSA_size(rsa), RSA_flags(rsa));
#endif
  ciphered_session_key = (uint8_t *)malloc(RSA_size(rsa));

  if(!ciphered_session_key) {
    fprintf(stderr, "\n%s:%d memory Allocation failed for ciphered session key\n",
           __FILE__,
           __LINE__);
    return(-4);
  }

  memset((void *)ciphered_session_key, 0, RSA_size(rsa));
  /*Encrypt Session key (256-bits) with public key*/
  cipher_len = RSA_public_encrypt(sizeof(pAuthCtx->session_key), 
                                  pAuthCtx->session_key,
                                  ciphered_session_key, 
                                  rsa,
                                  RSA_PKCS1_PADDING);
  if(cipher_len < 0) {
    fprintf(stderr, "\n%s:%d Encryption of session key with public key failed\n",
            __FILE__,
            __LINE__);
    return(-5);
  }

  X509_free(x509);
  RSA_free(rsa);
  EVP_PKEY_free(pkey);

  util_base64(ciphered_session_key, 
               cipher_len, 
               b64_cipher, 
               &b64_cipher_len);

  memset((void *)b64_skey, 0, b64_skey_size);
  snprintf(b64_skey,
           b64_skey_size,
           "%s%s%s%s%s",
           "<Skey ci=\"",
           not_after,
           "\">",
           b64_cipher,
           "</Skey>");

  return(0); 
}/*auth_skey*/

int32_t auth_compose_xml(uint8_t *auth_xml,
                         uint16_t auth_xml_size,
                         uint16_t *auth_xml_len,
                         uint8_t *uses,
                         uint8_t *meta,
                         uint8_t *skey,
                         uint8_t *hmac,
                         uint8_t *data) {

  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  *auth_xml_len = snprintf(auth_xml, 
           auth_xml_size,
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s",
           "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
           "<Auth xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request/",
           pAuthCtx->version,
           "\" ac=\"" ,
           pAuthCtx->ac,
           "\" lk=\"",
           pAuthCtx->lk,
           "\" rc=\"",
           pAuthCtx->rc,
           "\" sa=\"", 
           pAuthCtx->sa,
           "\" tid=\"",
           pAuthCtx->tid,
           "\" txn=\"",
           pAuthCtx->txn,
           "\" uid=\"",
           pAuthCtx->uid,
           "\" ver=\"",
           pAuthCtx->version,
           "\">",
           "\n  ",
           uses,
           "\n  ",
           meta,
           "\n  ",
           skey,
           "\n  ",
           hmac,
           "\n  ",
           data,
           "\n");
           
  return(0);
}/*auth_compose_xml*/

int32_t auth_c14n_auth_xml(uint8_t *c14n_auth_xml, 
                           uint16_t c14n_auth_xml_size, 
                           uint8_t *c14n_uses, 
                           uint8_t *c14n_meta, 
                           uint8_t *skey, 
                           uint8_t *hmac, 
                           uint8_t *data) {

  auth_ctx_t *pAuthCtx = &auth_ctx_g;

  memset((void *)c14n_auth_xml, 0, c14n_auth_xml_size);

  snprintf(c14n_auth_xml, 
           c14n_auth_xml_size,
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s",
           "<Auth xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request/",
           pAuthCtx->version,
           "\" ac=\"" ,
           pAuthCtx->ac,
           "\" lk=\"",
           pAuthCtx->lk,
           "\" rc=\"",
           pAuthCtx->rc,
           "\" sa=\"", 
           pAuthCtx->sa,
           "\" tid=\"",
           pAuthCtx->tid,
           "\" txn=\"",
           pAuthCtx->txn,
           "\" uid=\"",
           pAuthCtx->uid,
           "\" ver=\"",
           pAuthCtx->version,
           "\">",
           "\n  ",
           c14n_uses,
           "\n  ",
           c14n_meta,
           "\n  ",
           skey,
           "\n  ",
           hmac,
           "\n  ",
           data,
           "\n  \n",
           "</Auth>");
  //fprintf(stderr, "\n%s:%d c14n_auth_xml %s\n", __FILE__, __LINE__, c14n_auth_xml);
  return(0);
}/*auth_c14n_auth_xml*/

int32_t auth_c14n_sign(uint8_t *c14n_auth_xml,
                       uint8_t *b64_digest,
                       uint8_t *b64_signature,
                       uint8_t *b64_subject,
                       uint8_t *b64_certificate) {

  uint8_t digest[20];
  uint32_t digest_len;
  uint16_t b64_digest_len = 0;
  uint8_t c14n_signed_info[2048];
  uint16_t c14n_signed_info_len = 0;
  uint8_t *signature_value = NULL;
  uint16_t signature_len;
  uint16_t b64_signature_len;
  uint8_t *subject = NULL;
  uint16_t subject_len = 0;
  uint8_t *certificate = NULL;
  uint16_t certificate_len = 0;

  memset((void *)digest, 0, sizeof(digest));
  util_compute_digest(c14n_auth_xml, 
                       strlen(c14n_auth_xml), 
                       digest, 
                       &digest_len);

  util_base64(digest, 
               digest_len, 
               b64_digest, 
               &b64_digest_len);

  memset((void *)c14n_signed_info, 0, sizeof(c14n_signed_info)); 
  util_c14n_signedinfo(c14n_signed_info, 
                        sizeof(c14n_signed_info), 
                        &c14n_signed_info_len,
                        b64_digest);

  util_compute_rsa_signature(c14n_signed_info, 
                              c14n_signed_info_len, 
                              &signature_value, 
                              &signature_len); 

  util_base64(signature_value, 
               signature_len, 
               b64_signature, 
               &b64_signature_len);  

  util_subject_certificate(&subject,
                            &subject_len,
                            &certificate,
                            &certificate_len);

  /*copy subject and certificate*/
  strncpy(b64_subject, subject, subject_len);
  strncpy(b64_certificate, certificate, certificate_len);
  
  free(signature_value);
  signature_value = NULL;
  free(subject);
  free(certificate);

  return(0);
}/*auth_c14n_sign*/

int32_t auth_auth_xml(uint8_t *auth_xml, 
                      uint32_t auth_xml_size, 
                      uint8_t *pid_xml,
                      uint8_t *pid_uses_opt) {
  uint8_t uses[512];
  uint16_t uses_size = sizeof(uses);
  uint8_t c14n_uses[512];
  uint16_t c14n_uses_size = sizeof(c14n_uses);
  uint8_t meta[256];
  uint16_t meta_size = sizeof(meta);
  uint8_t c14n_meta[512];
  uint16_t c14n_meta_size = sizeof(c14n_meta);
  uint8_t skey[1024];
  uint16_t skey_size = sizeof(skey);
  uint8_t pid_otp_xml[1024];
  uint16_t pid_otp_xml_size = sizeof(pid_otp_xml);
  uint8_t hmac[1024];
  uint16_t hmac_size = sizeof(hmac);
  uint8_t data[1024];
  uint16_t data_size = sizeof(data);
  uint16_t auth_xml_len = 0;
  uint8_t b64_digest[1024];
  uint8_t b64_signature[2048];
  uint8_t b64_subject[1024];
  uint8_t b64_certificate[2048];
  uint16_t tmp_len = 0;

  /*Uses Tag of Final AUTH XML <Uses .../>*/  
  auth_uses(uses, 
            uses_size, 
            c14n_uses, 
            c14n_uses_size,
            pid_uses_opt);

  /*Meta tag of Final AUTH xml <Meta .../>*/
  auth_meta(meta, 
            meta_size, 
            c14n_meta, 
            c14n_meta_size);

  /*Skey tag of Final AUTH XML <Skey ..></Skey>*/
  auth_skey(skey, skey_size);

  /*Hmac tag of Final XML <Hmac ...></Hmac>*/
  auth_hmac(hmac, 
            hmac_size,
            pid_xml);

  /*Data tag of Final AUTH XML <Data ...></Data>*/
  auth_data(data, data_size, pid_xml);

  /*c14n auth XML*/
  auth_c14n_auth_xml(auth_xml, 
                     auth_xml_size, 
                     c14n_uses, 
                     c14n_meta, 
                     skey, 
                     hmac, 
                     data);

  /*compute the digest, signature, subject and certificate*/
  memset((void *)b64_digest, 0, sizeof(b64_digest));
  memset((void *)b64_signature, 0, sizeof(b64_signature));
  memset((void *)b64_subject, 0, sizeof(b64_subject));
  memset((void *)b64_certificate, 0, sizeof(b64_certificate));

  auth_c14n_sign(auth_xml,
                 b64_digest,
                 b64_signature,
                 b64_subject,
                 b64_certificate);

  memset((void *)auth_xml, 0, auth_xml_size);
  auth_compose_xml(auth_xml,
                   auth_xml_size,
                   &tmp_len,
                   uses,
                   meta,
                   skey,
                   hmac,
                   data);

  util_compose_final_xml((uint8_t *)&auth_xml[tmp_len], 
                          (auth_xml_size - tmp_len), 
                          &auth_xml_len,
                          /*digest*/
                          b64_digest,
                          /*Signature Value*/
                          b64_signature,
                          /*Subject Name*/
                          b64_subject,
                          /*Certificate*/
                          b64_certificate); 
  auth_xml_len += tmp_len;
  snprintf(&auth_xml[auth_xml_len], 
           auth_xml_size, 
           "%s", 
           "</Auth>");

  /*Writing xml into file*/
  auth_dump_xml(auth_xml, strlen(auth_xml));
  return(0);
}/*auth_auth_xml*/

int32_t auth_req_auth(uint8_t **req_xml, 
                      uint32_t req_xml_size, 
                      uint32_t *req_xml_len, 
                      uint8_t *auth_xml,
                      uint8_t *uid) {

  auth_ctx_t *pAuthCtx = &auth_ctx_g;

  memset((void *)req_xml, 0, req_xml_size);

  *req_xml_len = snprintf(*req_xml, 
           req_xml_size,
           "%s%s%s%s%s"
           "%s%s%c%s%c"
           "%s%s%s%s%s"
           "%s%s%s%s%d"
           "%s%s%s",
           "POST http://",
           pAuthCtx->uidai_host_name,
           "/",
           /*pAuthCtx->version*/"auth",
           "/",
           pAuthCtx->ac,
           "/",
           uid[0],
           "/",
           uid[1],
           "/",
           pAuthCtx->lk,
           " HTTP/1.1\r\n",
           "Host: ",
           pAuthCtx->uidai_host_name,
           "\r\n",
           "Content-Type: text/xml\r\n",
           "Connection: Keep-Alive\r\n",
           "Content-Length: ",
           (int32_t)strlen(auth_xml),
           "\r\n",
           /*Payload delimeter*/
           "\r\n",
           auth_xml);

  return(0);           
}/*auth_req_auth*/

uint8_t *auth_get_pi_param(uint8_t (*pi_param)[2][64], 
                           const uint8_t *param_name) {

  int16_t idx;

  for(idx = 0; pi_param[idx]; idx++) {
    if(!strncmp(pi_param[idx][0], param_name, strlen(pi_param[idx][0]))) {
      /*Initialize it to zero*/
      return(pi_param[idx][1]);
    }
  }

  return(NULL);
}/*auth_get_pi_param*/

int32_t auth_auth_pi_xml(uint8_t *auth_xml, uint32_t auth_xml_size, uint8_t (*pi_param)[2][64]) {
  
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  /*the ts - timestamp format is YYYY-MM-DDThh:mm:ss */
  uint8_t ts[32];

  memset((void *)auth_xml, 0, auth_xml_size);

  memset((void *)ts, 0, sizeof(ts));
  auth_compute_ts(ts, sizeof(ts));

  snprintf(auth_xml,
           auth_xml_size,
           "%s%s%s%s%s"
           "%s%s%s%s%s"
           "%s%s%s%s%s",
           "<Pid xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request-data/",
           pAuthCtx->version,
           "\" ts=\"",
           ts,
           "\" ver=\"",
           pAuthCtx->version,
           "\" wadh=\"\">\n",
           "  <Demo>\n",
           "    <Pi ms=\"",
           auth_get_pi_param(pi_param, "ms"),
           "\" name=\"",
           auth_get_pi_param(pi_param, "name"),
           "\"/>\n",
           "  </Demo>\n",
           "</Pid>");

}/*auth_auth_pi_xml*/

int32_t auth_process_auth_pi_req(int32_t conn_fd, 
                                 uint8_t *req_ptr,
                                 uint8_t **req_xml,
                                 uint32_t req_xml_size,
                                 uint32_t *req_xml_len) {
 
  /*"/request?type=auth&subtype=pi&uid=12345678&name=123456&ms=E&cell_no=9701361361&email_id=";*/
  uint8_t pi[512];
  uint8_t *uid;
  uint8_t auth_xml[6000];
  uint32_t auth_xml_size = sizeof(auth_xml);
  uint8_t *param_str = NULL;
  uint8_t pi_param[16][2][64];
  uint16_t pi_idx = 0;
  uint8_t param_value[64];
  uint8_t pid_pi_xml[512];
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  
 
  memset((void *)pi, 0, sizeof(pi));
  memset((void *)uid, 0, sizeof(uid));
 
  /*Suppress the character string until ?*/ 
  sscanf(req_ptr, 
         "%*[^?]?%s",
         pi);

  fprintf(stderr, "\npi str is %s\n", pi);
  param_str = strtok(pi, "&");
  memset((void *)pi_param, 0, sizeof(pi_param));

  do {
    sscanf(param_str, "%[^=]=%s", pi_param[pi_idx][0], pi_param[pi_idx][1]);
    pi_idx++;

  }while(param_str = strtok(NULL, "&"));

  /*Make sure that last row is terminated with NULL character*/
  pi_param[pi_idx][0][0] = '\0';
  pi_param[pi_idx][1][0] = '\0';

  uid = auth_get_pi_param(pi_param, "uid");
  fprintf(stderr, "\n%s:%d uid %s \n", __FILE__, __LINE__, uid);
  strncpy(pAuthCtx->uid, uid, strlen(uid));

  /*Preparing Pi node of the Auth root element*/
  auth_auth_pi_xml(pid_pi_xml,
                   sizeof(pid_pi_xml),
                   pi_param);
  fprintf(stderr, "\n%s:%d PID XML \n%s\n", __FILE__, __LINE__, pid_pi_xml);
  /*pi attribute of Uses to be set to "y"*/
  auth_auth_xml(auth_xml,
                auth_xml_size,
                pid_pi_xml,
                "pi");

  /*Pre-pending HTTP/1.1 Header*/
  auth_req_auth(req_xml, 
                req_xml_size, 
                req_xml_len, 
                auth_xml, 
                uid);

  return(0); 
}/*auth_process_auth_pi_req*/

int32_t auth_process_auth_otp_req(int32_t conn_fd, 
                                  uint8_t *req_ptr,
                                  uint8_t **req_xml,
                                  uint32_t req_xml_size,
                                  uint32_t *req_xml_len) {

  /*"/request?type=auth&subtype=otp&otp-value=123456&uid=999999990019&txn=8SampleClient";*/
  uint8_t otp_value[32];
  uint8_t uid[16];
  uint8_t txn[64];
  uint8_t ts[32];
  uint16_t ts_size = sizeof(ts);
  uint8_t auth_xml[6000];
  uint16_t auth_xml_size = sizeof(auth_xml);
  uint8_t pid_otp_xml[256];
  auth_ctx_t *pAuthCtx = &auth_ctx_g;
 
  memset((void *)otp_value, 0, sizeof(otp_value));
  memset((void *)uid, 0, sizeof(uid));
  memset((void *)txn, 0, sizeof(txn));
  
  sscanf(req_ptr, 
         "%*[^?]?%*[^&]&%*[^&]&%*[^=]=%[^&]&%*[^=]=%[^&]&%*[^=]=%s",
         otp_value,
         uid,
         txn);
  fprintf(stderr, "\n%s:%d otp_value %s uid %s txn %s\n", __FILE__, __LINE__, otp_value, uid, txn);
  strncpy(pAuthCtx->uid, uid, strlen(uid));
  strncpy(pAuthCtx->txn, txn, strlen(txn));
  
  auth_compute_ts(ts, ts_size);

  /*PID for OTP XML*/
  auth_pid_otp(pid_otp_xml, 
               sizeof(pid_otp_xml), 
               otp_value, 
               ts);

  auth_auth_xml(auth_xml,
                auth_xml_size,
                pid_otp_xml,
                "otp");

  /*Pre-pending HTTP/1.1 Header*/
  auth_req_auth(req_xml, 
                req_xml_size, 
                req_xml_len, 
                auth_xml, 
                uid);

  return(0);
}/*auth_process_auth_otp_req*/

int32_t auth_process_req(int32_t conn_fd, 
                         uint8_t *req_ptr,
                         uint8_t **req_xml,
                         uint32_t req_xml_size,
                         uint32_t *req_xml_len) {

  auth_ctx_t *pAuthCtx = &auth_ctx_g;
  uint8_t req_sub_type[64];
 
  memset((void *)req_sub_type, 0, sizeof(req_sub_type));

  /*%*[^?] meaning match ? and suppress it i.e do not store into any variable*/ 
  sscanf(req_ptr, 
         "%*[^?]?%*[^=]=%*[^&]&%*[^=]=%[^&]&",
         req_sub_type);

  fprintf(stderr, "\n%s:%d sub type %s\n", __FILE__, __LINE__,req_sub_type);

  if(!strncmp(req_sub_type, "otp", 3)) {
    auth_process_auth_otp_req(conn_fd, 
                              req_ptr, 
                              req_xml, 
                              req_xml_size, 
                              req_xml_len);

  } else if(!strncmp(req_sub_type, "pi", 2)) {
    auth_process_auth_pi_req(conn_fd, 
                             req_ptr,
                             req_xml,
                             req_xml_size,
                             req_xml_len);

  } else if(!strncmp(req_sub_type, "pa", 2)) {
    //auth_process_auth_pa_req(conn_fd, req_ptr);

  } else if(!strncmp(req_sub_type, "pfa", 3)) {
    //auth_process_auth_pfa_req(conn_fd, req_ptr);
    
  } else if(!strncmp(req_sub_type, "kyc", 3)) {
    //auth_process_auth_kyc_req(conn_fd, req_ptr);
    
  }

}/*auth_process_req*/

int32_t auth_main(int32_t conn_fd, 
                  uint8_t *req_ptr, 
                  uint32_t req_len, 
                  uint8_t **rsp_ptr, 
                  uint32_t *rsp_len) {
 
  uint32_t rsp_ptr_size = 6000;
 
  //uint8_t *req_ptr = "/request?type=auth&subtype=otp&otp-value=577023&uid=999999990019&txn=8SampleClient";
  //uint8_t *req_ptr = "/request?type=auth&version=1.6&subtype=pi&name=Shivshankar+Choudhury&uid=999999990019&ms=E";
  /*"/request?type=auth&subtype=pi&uid=12345678&name=123456&ms=E&cell_no=9701361361&email_id=";*/

  *rsp_ptr = (uint8_t *)malloc(rsp_ptr_size);
  assert(*rsp_ptr != NULL); 
  memset((void *)(*rsp_ptr), 0, rsp_ptr_size);

  auth_process_req(conn_fd, 
                   req_ptr, 
                   rsp_ptr, 
                   rsp_ptr_size, 
                   rsp_len);

  fprintf(stderr, "\n%s:%d command request \n%s\n", __FILE__, __LINE__, req_ptr);
  fprintf(stderr, "\n%s:%d Req XML \n%s\n", __FILE__, __LINE__, *rsp_ptr);
  
  return(0);
}/*auth_main*/

#endif /* __AUTH_C__ */