#ifndef __OTP_C__
#define __OTP_C__

#include <type.h>
#include <sys/stat.h>
#include <netdb.h>
#include <assert.h>
#include <common.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <otp.h>

otp_ctx_t otp_ctx_g;

int32_t otp_init(uint8_t *ac,
                 uint8_t *sa,
                 /*license key*/
                 uint8_t *lk,
                 uint8_t *private_key_file,
                 uint8_t *public_key_file,
                 uint32_t nas_ip,
                 uint16_t nas_port,
                 uint8_t *uidai_host_name) {

  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

  memset((void *)pOtpCtx, 0, sizeof(otp_ctx_t));

  strncpy(pOtpCtx->ac, (const char *)ac, strlen((const char *)ac));
  strncpy(pOtpCtx->sa, (const char *)sa, strlen((const char *)sa));
  strncpy(pOtpCtx->lk, (const char *)lk, strlen((const char *)lk));
  strncpy(pOtpCtx->type, "A", 1);
  strncpy(pOtpCtx->ver, "1.6", 3);

  strncpy(pOtpCtx->private_key_file, 
          (const char *)private_key_file, 
          strlen((const char *)private_key_file));

  strncpy(pOtpCtx->public_key_file, 
          (const char *)public_key_file, 
          strlen((const char *)public_key_file));
  /*00 - Send OTP via both SMS & e-mail
   *01 - Send OTP via SMS only
   *02 - Send OTP via e-mail only
   */
  pOtpCtx->ch = 0x00;

  pOtpCtx->nas_port = nas_port;
  pOtpCtx->nas_ip = nas_ip;

  strncpy(pOtpCtx->uidai_host_name, 
          (const char *)uidai_host_name, 
          strlen((const char *)uidai_host_name));

  pOtpCtx->uidai_port = 80;

  int32_t fd;

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d Creation of Socket failed\n", 
                    __FILE__, 
                    __LINE__);
    return(-1);
  }
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(pOtpCtx->nas_port);
  addr.sin_addr.s_addr = htonl(pOtpCtx->nas_ip);
  memset((void *)addr.sin_zero, 0, sizeof(addr.sin_zero));
 
  if(bind(fd, (struct sockaddr *)&addr, addr_len)) {
    fprintf(stderr, "\n%s:%d bind failed\n", __FILE__, __LINE__);
    return(-2);
  }

  listen(fd, 5/*number of simultaneous connection*/);
  pOtpCtx->nas_fd = fd;

  pOtpCtx->otp_fd = -1;
  close(fd);
  return(0);
}/*otp_init*/

int32_t otp_compute_rsa_signature(uint8_t *signed_info, 
                                  uint16_t signed_info_len, 
                                  uint8_t **signature_value, 
                                  uint16_t *signature_len) {
  BIO *bio = NULL;
  RSA *rsa = NULL;
  uint8_t *pkey = NULL;
  int32_t fd;
  int32_t ret = -1;
  struct stat stat_buff;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  fd = open(pOtpCtx->private_key_file, O_RDONLY);
  
  if(fd < 0) {
    fprintf(stderr, "\n%s:%d Opening of file %s Failed\n", 
                    __FILE__,
                    __LINE__,
                    pOtpCtx->private_key_file);
    return(-1);
  }
 
  if(fstat(fd, &stat_buff)) {
    fprintf(stderr, "\n%s:%d fstat failed\n",
                    __FILE__,
                    __LINE__);
    return(-2);
  }
  /*File stats are fetched successfully.*/
  pkey = (uint8_t *)malloc(stat_buff.st_size);

  if(!pkey) {
    fprintf(stderr, "\n%s:%d Memory Allocation Failed\n",
                    __FILE__,
                    __LINE__);
    return(-2);
  }

  memset((void *)pkey, 0, stat_buff.st_size);
  if(stat_buff.st_size != read(fd, pkey, stat_buff.st_size)) {
    fprintf(stderr, "\n%s:%d Reading of file failed\n",
                     __FILE__,
                     __LINE__);
    return(-3);
  }

  close(fd);
  bio = BIO_new_mem_buf(pkey, stat_buff.st_size);
  rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
  (*signature_value) = malloc(RSA_size(rsa));

  if(!(*signature_value)) { 
    fprintf(stderr, "\n%s:%d Allocation of memory Failed\n",
                    __FILE__,
                    __LINE__);
    RSA_free(rsa);
    BIO_free(bio);
    return(-5);
  }

  ret = RSA_sign(NID_sha1, 
                signed_info, 
                (uint32_t)signed_info_len, 
                *signature_value, 
                (uint32_t *)signature_len, 
                rsa);

  if(1 != ret) {
    fprintf(stderr, "\n%s:%d RSA sigining failed\n",
                    __FILE__,
                    __LINE__);
    BIO_free(bio);
    RSA_free(rsa);
    return(-6);
  }

 return(0); 
}/*otp_compute_rsa_signature*/

int32_t otp_compute_rsa_key_value(uint8_t **modulus, 
                                  uint16_t *modulus_len, 
                                  uint8_t **exponent, 
                                  uint16_t *exponent_len) {

  RSA *rsa = NULL;
  EVP_PKEY *evpkey = NULL;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  FILE *fp;
  X509 *x509 = NULL;
  int32_t ret = -1;

  ERR_load_crypto_strings();
  fp = fopen(pOtpCtx->public_key_file,"r");
  assert(fp != NULL);
  
  x509 = PEM_read_X509(fp, NULL, 0, NULL);
  fclose(fp);
  evpkey = X509_get_pubkey(x509);

  /*For openssl-1.1.0e*/
  rsa = EVP_PKEY_get1_RSA(evpkey); 
  /*Retrieving Modulus - Public Key*/ 
  *modulus_len = BN_num_bytes(rsa->n);
  assert(*modulus_len > 0);

  (*modulus) = (uint8_t *)malloc(*modulus_len);
  memset((void *)(*modulus), 0, *modulus_len);
  assert((*modulus) != NULL);

  ret = BN_bn2bin(rsa->n, (*modulus));
  assert(ret == *modulus_len);  

  /*Retrieving exponent*/
  *exponent_len = BN_num_bytes(rsa->e);
  assert(*exponent_len > 0);
  (*exponent) = (uint8_t *)malloc(*exponent_len);
  assert((*exponent) != NULL);
  memset((void *)(*exponent), 0, *exponent_len);
  ret = BN_bn2bin(rsa->e, (*exponent));
  assert(ret == *exponent_len);

  X509_free(x509);
  RSA_free(rsa);
  EVP_PKEY_free(evpkey);

  return(0);
}/*otp_compute_rsa_key_value*/

int32_t otp_build_c14n_signedinfo_tag(uint8_t *c14n,
                                      uint16_t c14n_max_size,
                                      uint16_t *c14n_len,
                                      uint8_t *sha1_digest) {
  int32_t ret = -1;

  ret = snprintf(c14n,
                 c14n_max_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s",
                 "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n",
                 "  <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>\n",
                 "  <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>\n",
                 "  <Reference URI=\"\">\n",
                 "    <Transforms>\n",
                 "      <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform>\n",
                 "    </Transforms>\n",
                 "    <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n",
                 "    <DigestValue>",sha1_digest,"</DigestValue>\n",
                 "  </Reference>\n",
                 "</SignedInfo>");


}/*otp_build_c14n_signedinfo_tag*/

int32_t otp_build_c14n_otp_tag(uint8_t *c14n, 
                               uint16_t c14n_max_size, 
                               uint16_t *c14n_len) {
  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  ret = snprintf(c14n,
                 c14n_max_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%d%s"
                 "%s%s",
                 "<Otp xmlns=\"http://www.w3.org/2000/09/xmldsig#\" uid=\"",
                 pOtpCtx->uid,
                 "\" tid=\"public\"",
                 " ac=\"",
                 pOtpCtx->ac,
                 "\" sa=\"",
                 pOtpCtx->sa,
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 pOtpCtx->ver,
                 "\" txn=\"",
                 pOtpCtx->txn,
                 "\"",
                 " lk=\"",
                 pOtpCtx->lk,
                 "\" type=\"",
                 pOtpCtx->type,
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*otps tag starts*/
                 "  <Opts ch=\"",
                 pOtpCtx->ch,
                 "\"></Opts>",
                 "  \n",
                 "</Otp>");

  *c14n_len = ret;

  return(0);
}/*otp_build_c14n_otp_tag*/

/*
  1.Canonicalize* the text-to-be-signed, C = C14n(T).
  2.Compute the message digest of the canonicalized text, m = Hash(C).
  3.Encapsulate the message digest in an XML <SignedInfo> element, SI, in canonicalized form.
  4.Compute the RSA signatureValue of the canonicalized <SignedInfo> element, SV = RsaSign(Ks, SI).
  5.Compose the final XML document including the signatureValue, this time in non-canonicalized form.

 */
int32_t otp_sign_xml(uint8_t **signed_xml, 
                     uint16_t *signed_xml_len) {

  uint8_t c14n_otp_xml[5096];
  uint16_t c14n_otp_xml_len;
  uint8_t otp_digest[20];
  uint8_t otp_b64[2024];
  uint16_t otp_b64_len;
  uint8_t otp_b64_signature[2024];
  uint16_t otp_b64_signature_len;
  uint8_t c14n_otp_signed_info_xml[5096];
  uint16_t c14n_otp_signed_info_xml_len;
  uint8_t *signature_value = NULL;
  uint16_t signature_value_len = 0;
  uint8_t *modulus = NULL;
  uint16_t modulus_len = 0;
  uint8_t modulus_b64[2048];
  uint16_t modulus_b64_len;
  uint8_t *exponent = NULL;
  uint16_t exponent_len = 0;
  uint8_t exponent_b64[2048];
  uint16_t exponent_b64_len;

  memset((void *)c14n_otp_xml, 0, sizeof(c14n_otp_xml));
  /*C14N - Canonicalization of <otp> portion of xml*/
  otp_build_c14n_otp_tag(c14n_otp_xml, 
                         sizeof(c14n_otp_xml), 
                         &c14n_otp_xml_len);

  memset((void *)otp_digest, 0, sizeof(otp_digest));
  otp_compute_digest(c14n_otp_xml, c14n_otp_xml_len, otp_digest);

  memset((void *)otp_b64, 0, sizeof(otp_b64));
  otp_b64_len = 0;
  otp_compute_b64(otp_digest, sizeof(otp_digest), otp_b64, &otp_b64_len);

  /*C14N for <SignedInfo> portion of xml*/
  otp_build_c14n_signedinfo_tag(c14n_otp_signed_info_xml, 
                                sizeof(c14n_otp_signed_info_xml), 
                                &c14n_otp_signed_info_xml_len, 
                                otp_b64);
#if 0
  memset((void *)otp_digest, 0, sizeof(otp_digest));
  otp_compute_digest(c14n_otp_signed_info_xml, 
                     c14n_otp_signed_info_xml_len, 
                     otp_digest);
  
  memset((void *)otp_b64, 0, sizeof(otp_b64));
  otp_b64_len = 0;
  otp_compute_b64(otp_digest, sizeof(otp_digest), otp_b64, &otp_b64_len);
#endif  
  /*Creating RSA Signature - by signing digest with private key*/
  otp_compute_rsa_signature(c14n_otp_signed_info_xml, 
                            c14n_otp_signed_info_xml_len, 
                            &signature_value, 
                            &signature_value_len);

  memset((void *)otp_b64_signature, 0, sizeof(otp_b64_signature));
  otp_b64_signature_len = 0;
  otp_compute_b64(signature_value, 
                  signature_value_len, 
                  otp_b64_signature, 
                  &otp_b64_signature_len);

  /*Extracting Modulus and exponent from public key*/
  otp_compute_rsa_key_value(&modulus, 
                            &modulus_len, 
                            &exponent, 
                            &exponent_len);

  memset((void *)modulus_b64, 0, sizeof(modulus_b64));
  modulus_b64_len = 0;
  otp_compute_b64(modulus, modulus_len, modulus_b64, &modulus_b64_len);

  memset((void *)exponent_b64, 0, sizeof(exponent_b64));
  exponent_b64_len = 0;
  otp_compute_b64(exponent, exponent_len, exponent_b64, &exponent_b64_len);

  /*Create the Final signed xml*/ 
  (*signed_xml) = (uint8_t *)malloc(10000000);
  assert((*signed_xml) != NULL);
  memset((void *)(*signed_xml), 0, 10000000); 
  otp_compose_final_xml((*signed_xml), 
                        10000000, 
                        signed_xml_len,
                        /*digest*/
                        otp_b64,
                        /*Signature Value*/
                        otp_b64_signature,
                        /*RSA Modulus*/
                        modulus_b64,
                        /*RSA exponent*/
                        exponent_b64); 

  free(modulus);
  modulus = NULL;
  free(exponent);
  exponent = NULL;
  free(signature_value);
  signature_value = NULL;
}/*otp_sign_xml*/


/**
 * We use the SHA-1 message digest function, which outputs a hash value 20 bytes long
 */

int32_t otp_compute_digest(uint8_t *otp_xml, 
                           uint16_t otp_xml_len, 
                           uint8_t *digest) {
  SHA_CTX ctx;

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, otp_xml, otp_xml_len);
  SHA1_Final(digest, &ctx);

  OPENSSL_cleanse(&ctx, sizeof(ctx));

  return(0);
}/*otp_compute_digest*/ 

int32_t otp_compute_b64(uint8_t *sha1, 
                        uint16_t sha1_len, 
                        uint8_t *b64, 
                        uint16_t *b64_len) {

  uint16_t offset;
  uint16_t idx = 0;
  uint32_t tmp = 0;
  uint8_t b64_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

  if(!sha1 || !sha1_len || !b64) {
    return -1;
  }

  for(offset = 0; offset < sha1_len; offset +=3)
  {
    if(sha1_len - offset >= 3)
    {
      tmp = ((sha1[offset] << 8 |
              sha1[offset + 1]) << 8 |
              sha1[offset + 2]) & 0xFFFFFF;

      b64[idx++] = b64_set[(tmp >> 18)  & 0x3F];
      b64[idx++] = b64_set[(tmp >> 12)  & 0x3F];
      b64[idx++] = b64_set[(tmp >> 6 )  & 0x3F];
      b64[idx++] = b64_set[(tmp >> 0 )  & 0x3F];
    }
    else if((sha1_len - offset) == 1)
    {
      tmp = sha1[offset];

      b64[idx++] = b64_set[(tmp >> 2)  & 0x3F];
      b64[idx++] = b64_set[(tmp << 4)  & 0x3F];
      b64[idx++] = '=';
      b64[idx++] = '=';

    }
    else if((sha1_len - offset) == 2)
    {
      tmp = (sha1[offset] << 8 |
             sha1[offset + 1]) & 0xFFFF;

      b64[idx++] = b64_set[(tmp >> 10)  & 0x3F];
      b64[idx++] = b64_set[(tmp >>  3)  & 0x3F];
      b64[idx++] = b64_set[(tmp <<  3)  & 0x3F];
      b64[idx++] = '=';
    }
  }

  *b64_len = idx;

  return (0);
}/*otp_compute_b64*/

  
int32_t otp_compose_final_xml(uint8_t *out_xml, 
                              uint32_t out_xml_max_size, 
                              uint16_t *out_xml_len,
                              uint8_t *digest_b64,
                              uint8_t *signature_b64,
                              uint8_t *modulus_b64,
                              uint8_t *exponent_b64) {

  int32_t ret = -1;
  uint16_t otp_xml_len = 0;
  otp_compose_otp_xml(out_xml,
                      out_xml_max_size,
                      &otp_xml_len); 

  ret = snprintf((char *)&out_xml[otp_xml_len],
                 (out_xml_max_size - otp_xml_len),
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s",
                 "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n",
                 "<SignedInfo>\n",
                 "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n",
                 "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n",
                 "<Reference URI=\"\">\n",
                 "<Transforms>",
                 "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n",
                 "</Transforms>\n",
                 "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n",
                 "<DigestValue>",
                 digest_b64,
                 "</DigestValue>\n",
                 "</Reference>\n",
                 "</SignedInfo>\n",
                 "<SignatureValue>",
                 signature_b64,
                 "</SignatureValue>\n",
                 "<KeyInfo>",
                 "<KeyValue>",
                 "<RSAKeyValue>",
                 "<Modulus>",
                 modulus_b64,
                 "</Modulus>\n",
                 "<Exponent>",
                 exponent_b64,
                 "</Exponent>\n",
                 "</RSAKeyValue>\n",
                 "</KeyValue>\n",
                 "</KeyInfo>\n",
                 "</Signature>\n",
                 "</Otp>\n");

  *out_xml_len = ret + otp_xml_len;

  return(0);
}/*otp_compose_final_xml*/


int32_t otp_compute_utf8(uint8_t *xml_in, 
                         uint16_t xml_in_len, 
                         uint8_t *utf8_set_out, 
                         uint16_t *utf8_set_len) {
  uint16_t idx;
  uint16_t utf8_idx;

  for(utf8_idx = 0, idx = 0; idx < xml_in_len; idx++, utf8_idx++) {

    if(*((uint16_t *)&xml_in[idx]) <= 0x7F) {
      /*Byte is encoded in single btye*/
      utf8_set_out[utf8_idx] = xml_in[idx];

    } else if(*((uint16_t *)&(xml_in[idx])) <= 0x7FF) {
      /*Byte is spread accross 2 Bytes*/
      utf8_set_out[utf8_idx++] = 0x80 | (xml_in[idx] & 0x3F);
      utf8_set_out[utf8_idx] = 0xC0 | ((xml_in[idx + 1] & 0x1F) | (xml_in[idx] >> 6));
      idx++; 
    } else if(*((uint8_t *)&xml_in[idx]) <= 0xFFFF) {
      /*Byte to be spread into 3 Bytes*/
      utf8_set_out[utf8_idx++] = 0x80 | (xml_in[idx] & 0x3F);
      utf8_set_out[utf8_idx++] = 0x80 | ((xml_in[idx + 1] & 0xF) | (xml_in[idx] >> 6));
      utf8_set_out[utf8_idx] = 0xE0 | (xml_in[idx + 1] >> 4);
      idx++;
      
    } else if(*((uint32_t *)&xml_in[idx]) <= 0x10FFFF) {
      /*Bytes to be spread into 4 Bytes*/
      
    } else {
      fprintf(stderr, "\n%s:%d Not Supported UTF-8 as of now\n",
                      __FILE__,
                      __LINE__);
    }
  }

  return(0);
}/*otp_compute_utf8*/

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
                            uint16_t *otp_xml_len) {
  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  ret = snprintf(otp_xml,
                 otp_xml_max_size,
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%s%s"
                 "%s%s%s%d%s",
                 "<?xml version=1.0 encoding=\"UTF-8\" standalone=\"yes\"?>\n",
                 "<Otp uid=\"",
                 pOtpCtx->uid,
                 "\" tid=\"public\"",
                 " ac=\"",
                 pOtpCtx->ac,
                 "\" sa=\"",
                 pOtpCtx->sa,
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 pOtpCtx->ver,
                 "\" txn=\"",
                 pOtpCtx->txn,
                 "\" lk=\"",
                 pOtpCtx->lk,
                 "\" type=\"",
                 pOtpCtx->type,
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*otps tag starts*/
                 "  <Opts ch=\"",
                 pOtpCtx->ch,
                 "\"/>\n");

  *otp_xml_len = ret;

  return(0);
}/*otp_compose_otp_xml*/

int32_t otp_request_otp(uint8_t *signed_xml, uint16_t signed_xml_len) {

  uint8_t *req_ptr = NULL;
  uint16_t req_len = 0;
  int32_t ret = -1;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  uint16_t req_max_len = signed_xml_len + 1024;
  
  req_ptr = (uint8_t *) malloc(req_max_len);
  assert(req_ptr != NULL);
  memset((void *)req_ptr, 0, req_max_len);

  /*Prepare http request*/
  ret = snprintf((char *)req_ptr,
                 req_max_len,
                 "%s%s%s%s%s"
                 "%s%s%d%s%d"
                 "%s%s%s%s%s"
                 "%s%s%s%s%d"
                 "%s",
                 /*https://<host>/otp/<ver>/<ac>/<uid[0]>/<uid[1]>/<asalk>*/
                 "POST ",
                 pOtpCtx->uidai_host_name,
                 "/otp/",
                 pOtpCtx->ver,
                 "/",
                 pOtpCtx->ac,
                 "/",
                 pOtpCtx->uid[0],
                 "/",
                 pOtpCtx->uid[1],
                 "/",
                 pOtpCtx->lk,
                 " HTTP/1.1\r\n",
                 "Host: ",
                 pOtpCtx->uidai_host_name,
                 "\r\n",
                 "Content-Type: text/xml\r\n",
                 "Connection: Keep-alive\r\n",
                 "Content-Length: ",
                 signed_xml_len,
                 /*delimeter B/W http header and its body*/
                 "\r\n\r\n\r\n");

  memcpy((void *)&req_ptr[ret], signed_xml, signed_xml_len);
  req_max_len = ret + signed_xml_len;
  
}/*otp_request_otp*/

int32_t otp_recv(int32_t conn_fd, 
                 uint8_t *packet_ptr, 
                 uint16_t *packet_len) {
  int32_t ret = -1;

  if(!packet_ptr) {
    *packet_len = 0;
  }

  ret = recv(conn_fd, packet_ptr, *packet_len, 0);

  if(ret > 0) {
    *packet_len = (uint16_t)ret;
  } else if(ret < 0) {
    *packet_len = 0;
  }

  return(0);
}/*otp_recv*/

int32_t otp_send(int32_t conn_fd, uint8_t *packet_ptr, uint16_t packet_len) {
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
      ret = 0;
    }

  }while(ret);

  return(0);
}/*otp_send*/

int32_t otp_connect_uidai(uint8_t *hostname) {
  struct hostent *he;
  struct in_addr **addr_list;
  int32_t i;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  struct sockaddr_in uidai_addr;
  socklen_t addr_len;
  int32_t fd;
  int32_t ret = -1;
  uint8_t ip_str[32];
  uint8_t ip[4];

  if(!(he = gethostbyname(hostname))) {
    // get the host info
    fprintf(stderr, "gethostbyname is returning an error\n");
    return (-1);
  }

  addr_list = (struct in_addr **) he->h_addr_list;

  for(i = 0; addr_list[i] != NULL; i++) {
    memset((void *)ip_str, 0, sizeof(ip_str));
    strcpy(ip_str ,inet_ntoa(*addr_list[i]));
    break;
  }
  
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if(fd < 0) {
    fprintf(stderr, "\n%s:%d socket creation failed\n",
                    __FILE__,
                    __LINE__);
    return(-2);
  }

  uidai_addr.sin_family = AF_INET;
  uidai_addr.sin_port = htons(pOtpCtx->uidai_port);

  sscanf((const char *)ip_str, 
         "%d.%d.%d.%d", 
         (int32_t *)&ip[0],
         (int32_t *)&ip[1],
         (int32_t *)&ip[2],
         (int32_t *)&ip[3]);

  uidai_addr.sin_addr.s_addr = (ip[0] << 24 | 
                                ip[1] << 16 | 
                                ip[2] <<  8 | 
                                ip[3]);

  memset((void *)uidai_addr.sin_zero, 0, sizeof(uidai_addr.sin_zero));
  addr_len = sizeof(uidai_addr);

  ret = connect(fd, (struct sockaddr *)&uidai_addr, addr_len);

  if(ret < 0) {
    fprintf(stderr, "\n%s:%d connection with uidai failed\n",
                    __FILE__,
                    __LINE__);
    return(-3);
  }

  pOtpCtx->otp_fd = fd;

  return (0);
}/*otp_connect_uidai*/

int32_t otp_process_otp_req(uint8_t *uid, int32_t conn_id) {

  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  uint8_t *req_ptr = NULL;
  uint16_t req_len = 0;

  strncpy(pOtpCtx->uid, uid, strlen((const char *)uid));
  snprintf(pOtpCtx->txn,
           sizeof(pOtpCtx->txn),
           "%d&SampleClient",
           conn_id);

  otp_sign_xml(&req_ptr, &req_len);

  if(pOtpCtx->otp_fd < 0) {
    otp_connect_uidai(pOtpCtx->uidai_host_name);
  }

  otp_send(pOtpCtx->otp_fd, req_ptr, req_len);

  free(req_ptr);
  return(0);
}/*otp_process_otp_req*/

int32_t otp_process_nas_req(int32_t conn_fd, 
                            uint8_t *packet_ptr, 
                            uint16_t packet_len) {
  uint8_t req_type[64];
  uint8_t req_subtype[64];
  uint8_t uri[64];
  uint8_t uid[16];

  sscanf((const char *)packet_ptr, 
         "%[^?]?type=%[^&]&", 
         uri, 
         req_type);

  if(!strncmp(req_type, "otp", 3)) {
    /*Extract the uid of 12 digits*/
    sscanf((const char *)packet_ptr, 
           "%*[^?]?%*[^&]&%s", 
           uid);
    otp_process_otp_req(uid, conn_fd);

  } else if(!strncmp(req_type, "auth", 4)) {
    /*Process Auth Request*/
  }

}/*otp_process_nas_req*/

int32_t otp_process_uidai_rsp(int32_t conn_fd, 
                              uint8_t *packet_ptr, 
                              uint16_t packet_len) {

  return(0);
}/*otp_process_uidai_rsp*/


/** @brief INPUT:
 *            T, text-to-be-signed, a byte string;
 *            Ks, RSA private key;
 *            OUTPUT: XML file, xml
 *              1.Canonicalize* the text-to-be-signed, C = C14n(T).
 *              2.Compute the message digest of the canonicalized text, m = Hash(C).
 *              3.Encapsulate the message digest in an XML <SignedInfo> element, SI, in canonicalized form.
 *              4.Compute the RSA signatureValue of the canonicalized <SignedInfo> element, SV = RsaSign(Ks, SI).
 *              5.Compose the final XML document including the signatureValue, this time in non-canonicalized form.
 *
 *
 */
void *otp_main(void *tid) {
  int32_t ret = -1;
  fd_set rd;
  int32_t max_fd = 0;
  struct timeval to;
  uint8_t buffer[1500];
  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  uint16_t buffer_len;
  int32_t connected_fd = -1;
  struct sockaddr_in peer_addr;
  socklen_t addr_len = sizeof(peer_addr);

  FD_ZERO(&rd);
  for(;;) {
    to.tv_sec = 2;
    to.tv_usec = 0;
    FD_SET(pOtpCtx->nas_fd, &rd);
    max_fd = max_fd > pOtpCtx->nas_fd ?max_fd: pOtpCtx->nas_fd;

    if(pOtpCtx->otp_fd > 0) {
      FD_SET(pOtpCtx->otp_fd, &rd);
      max_fd = max_fd > pOtpCtx->otp_fd? max_fd: pOtpCtx->otp_fd;
    }

    if(connected_fd > 0) {
      FD_SET(connected_fd, &rd);
      max_fd = max_fd > connected_fd? max_fd: connected_fd;
    }

    max_fd += 1;
   
    ret = select(max_fd, &rd, NULL, NULL, &to);

    if(ret > 0) {
      if(FD_ISSET(pOtpCtx->nas_fd, &rd)) {
        /*New Connection*/
        connected_fd = accept(pOtpCtx->nas_fd, 
                             (struct sockaddr *)&peer_addr, 
                             &addr_len);
      }
      
      if(FD_ISSET(connected_fd, &rd)) {
        /*Request received from NAS*/
        memset((void *)buffer, 0, sizeof(buffer));
        buffer_len = sizeof(buffer);
        otp_recv(connected_fd, buffer, &buffer_len);

        if(buffer_len) {
          otp_process_nas_req(connected_fd, buffer, buffer_len);
        }
      } 

      if((pOtpCtx->otp_fd > 0) && (FD_ISSET(pOtpCtx->otp_fd, &rd))) { 
        /*Response UIDAI Server*/
        memset((void *)buffer, 0, sizeof(buffer));
        buffer_len = sizeof(buffer);
        otp_recv(pOtpCtx->otp_fd, buffer, &buffer_len);

        if(buffer_len) {
          otp_process_uidai_rsp(pOtpCtx->otp_fd, buffer, buffer_len);
        }
      }
    }
  }

  return(0);
}/*otp_main*/
#endif /* __OTP_C__ */
