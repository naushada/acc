#ifndef __OTP_C__
#define __OTP_C__

#include <type.h>
#include <sys/stat.h>
#include <netdb.h>
#include <assert.h>
#include <common.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
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
  fprintf(stderr, "\n%s%d nas ip is 0x%X\n", __FILE__, __LINE__, nas_ip);
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
  memset((void *)pOtpCtx->uidai_subject_name, 
         0, 
         sizeof(pOtpCtx->uidai_subject_name));

  close(fd);
  return(0);
}/*otp_init*/


int32_t otp_get_subject_certificate(uint8_t **subject,
                                    uint16_t *subject_len,
                                    uint8_t **certificate,
                                    uint16_t *certificate_len) {

  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  uint8_t *tmp_str = pOtpCtx->uidai_subject_name;
  uint8_t *token = NULL;
  uint8_t buffer[2024];
  uint8_t tmp_buffer[2024];
  uint16_t offset = 0;
  int32_t rc = -1;
  FILE *fp;
  int32_t tmp_len = -1; 

  memset((void *)buffer, 0, sizeof(buffer));

  token = strtok(tmp_str, (const char *)"/");
 
  while(token != NULL) {

   //fprintf(stderr, "token %s\n", token);
   rc += snprintf((char *)&buffer[offset],
                  sizeof(buffer),
                  "%s,",
                  token);
   /*+1 for comma as a delimeter*/               
   offset += strlen((const char *)token) + 1;
   token = strtok(NULL, "/");
  }
 
  (*subject) = (uint8_t *)malloc(rc);

  memset((*subject), 0, rc);
  strncpy((*subject), buffer, rc);
  *subject_len = rc;
  //fprintf(stderr, "\nSubject Name %s\n", buffer);
  //fprintf(stderr, "\nSubject Name %s\n", (*subject));

  fp = fopen("tmp_cer", "r"); 

  if(!fp) {
    fprintf(stderr, "\nOpening of file tmp_cer failed\n");
    return(-1);
  }

  (*certificate) = (uint8_t *) malloc(sizeof(buffer));
  memset((void *)(*certificate), 0, sizeof(buffer));

  memset((void *)buffer, 0, sizeof(buffer));

  rc = fread(buffer, 1, sizeof(buffer), fp);
  fclose(fp);
  //fprintf(stderr, "rc = %d\n", rc);
  uint16_t tmp_rc = 0;
  offset = 0;

  memset((void *)tmp_buffer, 0, sizeof(tmp_buffer));
  /*eliminate the \n from buffer and store them into tmp_buffer*/
  while(rc > 0) {
    if(!strncmp((const char *)&buffer[tmp_rc], "-----BEGIN CERTIFICATE-----", 27)) {
      tmp_rc += 27 + 1;
      rc -= 27 + 1;
    } else if(!strncmp((const char *)&buffer[tmp_rc], "-----END CERTIFICATE-----", 25)) {
      tmp_rc+= 25;
      rc -= 25;
    } else {
      tmp_buffer[offset++] = buffer[tmp_rc];
      tmp_rc++;
      rc--;
    }
  }

  //fprintf(stderr, "tmp_buffer %s\n", tmp_buffer);
  /*-2 is to remove the \n from the end of the certificate*/
  strncpy((*certificate), tmp_buffer, (offset - 2));
  *certificate_len = offset - 2;
  //fprintf(stderr, "\ncertificate %s\n", (*certificate));
 
  return(0); 
}/*otp_get_subject_certificate*/

int32_t base64(uint8_t *input, uint16_t length, uint8_t *out_b64, uint16_t *b64_len) {

  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  memcpy(out_b64, bptr->data, bptr->length-1);
  out_b64[bptr->length-1] = 0;

  BIO_free_all(b64);
  *b64_len = bptr->length;
  return (0);
}/*base64*/

int32_t otp_compute_rsa_signature(uint8_t *signed_info, 
                                  uint16_t signed_info_len, 
                                  uint8_t **signature_value, 
                                  uint16_t *signature_len) {
  RSA *rsa = NULL;
  X509 *x509 = NULL;
  /*pkey - Private Key*/
  EVP_PKEY *pkey;
  EVP_MD_CTX *ctx;
  PKCS12 *p12;
  STACK_OF(X509) *ca = NULL;
  FILE *fp = NULL;
  int32_t fd;
  int32_t ret = -1;
  struct stat stat_buff;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  //fp = fopen(pOtpCtx->private_key_file, "r");
  fp = fopen("p_key", "r");
  x509 = X509_new();
  p12 = d2i_PKCS12_fp(fp, NULL);
  //PKCS12_parse(p12, "public", &pkey, &x509, &ca);
  PKCS12_parse(p12, "password", &pkey, &x509, &ca);
  PKCS12_free(p12);
  fclose(fp);
  /*storing subject key for later use*/
  X509_NAME_oneline(X509_get_subject_name(x509), 
                    pOtpCtx->uidai_subject_name, 
                    sizeof(pOtpCtx->uidai_subject_name));

  //fprintf(stderr, "%s:%d \n%s\n", __FILE__, __LINE__,pOtpCtx->uidai_subject_name);
  //fprintf(stderr, "\nCertificate\n");
  fp = fopen("tmp_cer", "w");
  PEM_write_X509(fp, x509);
  fclose(fp);

#if 0  
  fd = fileno(fp);
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
  //PEM_write_PrivateKey(stderr, pkey, NULL, NULL, 0, NULL, NULL);
#endif
  fp = fopen("p_key.pem", "r");
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  rsa = EVP_PKEY_get1_RSA(pkey);
 #if 0 
  if(!rsa) {
    fprintf(stderr, "\n%s:%d rsa is NULL\n", __FILE__, __LINE__);
    exit(0);
  }
  (*signature_value) = malloc(RSA_size(rsa));

  if(!(*signature_value)) { 
    fprintf(stderr, "\n%s:%d Allocation of memory Failed\n",
                    __FILE__,
                    __LINE__);
    RSA_free(rsa);
    return(-5);
  }

  /*A signing algorithm that, given a message and a private key, produces a signature*/
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
    fprintf(stderr, "err str %s\n", ERR_error_string(ERR_get_error(), NULL));
    RSA_free(rsa);
    return(-6);
  }
#endif 

  /*Initialize the message digest context*/
  ctx = EVP_MD_CTX_new();
  EVP_SignInit_ex(ctx, EVP_sha1(), NULL);
  /*signed_info is plain text*/
  EVP_SignUpdate(ctx, signed_info, signed_info_len);

  *signature_value = (uint8_t *)malloc(2048);
  memset((void *)*signature_value, 0, 2048);
  EVP_SignFinal(ctx, *signature_value, (uint32_t *)signature_len, pkey);
  fprintf(stderr, "\n%s:%d signature Value is %d\n", __FILE__, __LINE__, *signature_len); 

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  X509_free(x509);

  fprintf(stderr, "\nSI Sha1 Digest\n");
  for(ret = 0; ret < *signature_len; ret++) {
    fprintf(stderr, "%.2X", (*signature_value)[ret]);
  }
 return(0); 
}/*otp_compute_rsa_signature*/

int32_t otp_compute_rsa_key_value(uint8_t **modulus, 
                                  uint16_t *modulus_len, 
                                  uint8_t **exponent, 
                                  uint16_t *exponent_len) {

  RSA *rsa = NULL;
  const BIGNUM *n;
  const BIGNUM *e;
  const BIGNUM *d;
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

  fprintf(stderr, "\nPublic Certificate\n");
  PEM_write_X509(stderr, x509);
  
  evpkey = X509_get_pubkey(x509);

  PEM_write_PUBKEY(stderr, evpkey);
  /*Retrieving the subject name from */
  fprintf(stderr, "%s\n", X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0));
  
  /*For openssl-1.1.0e*/
  rsa = EVP_PKEY_get1_RSA(evpkey); 
  /*Retrieving Modulus - Public Key*/ 
  RSA_get0_key(rsa, &n, &e, &d); 
  *modulus_len = BN_num_bytes(n);
  assert(*modulus_len > 0);

  (*modulus) = (uint8_t *)malloc(*modulus_len);
  memset((void *)(*modulus), 0, *modulus_len);
  assert((*modulus) != NULL);

  ret = BN_bn2bin(n, (*modulus));
  assert(ret == *modulus_len);  

  /*Retrieving exponent*/
  *exponent_len = BN_num_bytes(e);
  assert(*exponent_len > 0);
  (*exponent) = (uint8_t *)malloc(*exponent_len);
  assert((*exponent) != NULL);
  memset((void *)(*exponent), 0, *exponent_len);
  ret = BN_bn2bin(e, (*exponent));
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
                 "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>\n",
                 "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>\n",
                 "      <Reference URI=\"\">\n",
                 "        <Transforms>\n",
                 "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform>\n",
                 "        </Transforms>\n",
                 "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n",
                 "        <DigestValue>",sha1_digest,"</DigestValue>\n",
                 "      </Reference>\n",
                 "    </SignedInfo>");

  *c14n_len = ret;
  //fprintf(stderr, "signed_info_tag_len %d strlen() %d\n", *c14n_len, strlen(c14n));
  return(0);
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
                 "%s%s%s%.2d%s"
                 "%s%s",
                 "<Otp xmlns=\"http://www.uidai.gov.in/authentication/otp/1.0\"",
                 " ac=\"",
                 pOtpCtx->ac,
                 "\" lk=\"",
                 pOtpCtx->lk,
                 "\" sa=\"",
                 pOtpCtx->sa,
                 "\" tid=\"public\"",
                 " txn=\"",
                 pOtpCtx->txn,
                 "\" type=\"",
                 pOtpCtx->type,
                 "\" uid=\"",
                 pOtpCtx->uid,
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 pOtpCtx->ver,
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*opts - options tag starts*/
                 "  <Opts ch=\"",
                 pOtpCtx->ch,
                 "\"></Opts>\n",
                 /*https://www.di-mgt.com.au/xmldsig2.html#c14nit*/
                 "  \n",
                 "</Otp>");

  *c14n_len = (uint16_t)ret;

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
  uint8_t otp_digest[1024];
  uint32_t otp_digest_len;
  uint8_t otp_b64[2024];
  uint16_t otp_b64_len;
  uint8_t otp_b64_signature[2024];
  uint16_t otp_b64_signature_len;
  uint8_t c14n_otp_signed_info_xml[5096];
  uint16_t c14n_otp_signed_info_xml_len;
  uint8_t *signature_value = NULL;
  uint16_t signature_value_len = 0;
  uint8_t *subject = NULL;
  uint16_t subject_len = 0;
  uint8_t *certificate = NULL;
  uint16_t certificate_len = 0;
  uint16_t idx;
  /*https://www.di-mgt.com.au/xmldsig2.html#twotypes*/
  uint8_t *test_data="<Envelope xmlns=\"http://example.org/envelope\">\n"
  "  <Body>\n"
  "    Olá mundo\n"
  "  </Body>\n"
  "  \n"
  "</Envelope>";
  uint8_t *test_data1 = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"
"      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>\n"
"      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>\n"
"      <Reference URI=\"\">\n"
"        <Transforms>\n"
"          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform>\n"
"        </Transforms>\n"
"        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n"
"        <DigestValue>UWuYTYug10J1k5hKfonxthgrAR8=</DigestValue>\n"
"      </Reference>\n"
"    </SignedInfo>";

  memset((void *)c14n_otp_xml, 0, sizeof(c14n_otp_xml));
  /*C14N - Canonicalization of <otp> portion of xml*/
  otp_build_c14n_otp_tag(c14n_otp_xml, 
                         sizeof(c14n_otp_xml), 
                         &c14n_otp_xml_len);

  fprintf(stderr, "\n%s:%d otp_tag\n%s\nlen %d\n", 
                  __FILE__, 
                  __LINE__, 
                  c14n_otp_xml, 
                  c14n_otp_xml_len);

  memset((void *)otp_digest, 0, sizeof(otp_digest));
#if 0
  otp_compute_digest(c14n_otp_xml, 
                     c14n_otp_xml_len, 
                     otp_digest, 
                     &otp_digest_len);
#endif

  otp_compute_digest(test_data, 
                     strlen(test_data), 
                     otp_digest, 
                     &otp_digest_len);

  fprintf(stderr, "\notp_digest_len is %d\n", otp_digest_len);
  for(idx = 0; idx < otp_digest_len; idx++) {
    fprintf(stderr, "%.2X", otp_digest[idx]);
  }

  memset((void *)otp_b64, 0, sizeof(otp_b64));
  otp_b64_len = 0;
  base64(otp_digest, otp_digest_len, otp_b64, &otp_b64_len);

  /*C14N for <SignedInfo> portion of xml*/
  otp_build_c14n_signedinfo_tag(c14n_otp_signed_info_xml, 
                                sizeof(c14n_otp_signed_info_xml), 
                                &c14n_otp_signed_info_xml_len, 
                                /*Message Digest in base64*/
                                otp_b64);

  fprintf(stderr, "\n%s:%d SI\n%s\nlen %d\n", 
                  __FILE__, 
                  __LINE__, 
                  c14n_otp_signed_info_xml, 
                  c14n_otp_signed_info_xml_len);
 
  memset((void *)otp_digest, 0, sizeof(otp_digest));
  otp_digest_len = 0;
  otp_compute_digest(test_data1, 
                     strlen(test_data1), 
                     otp_digest, 
                     &otp_digest_len);
  /*Creating RSA Signature - by signing digest with private key*/
  otp_compute_rsa_signature(test_data1, 
                            strlen(test_data1), 
                            &signature_value, 
                            &signature_value_len);
#if 0
  otp_compute_rsa_signature(c14n_otp_signed_info_xml, 
                            c14n_otp_signed_info_xml_len, 
                            &signature_value, 
                            &signature_value_len);
#endif

#if 0
  memset((void *)otp_digest, 0, sizeof(otp_digest));
  otp_digest_len = 0;
  otp_compute_digest(c14n_otp_signed_info_xml, 
                     c14n_otp_signed_info_xml_len, 
                     otp_digest, 
                     &otp_digest_len);

  otp_compute_rsa_signature(otp_digest, 
                            otp_digest_len, 
                            &signature_value, 
                            &signature_value_len);

#endif

  memset((void *)otp_b64_signature, 0, sizeof(otp_b64_signature));
  otp_b64_signature_len = 0;
#if 0
  otp_compute_b64(signature_value, 
                  signature_value_len, 
                  otp_b64_signature, 
                  &otp_b64_signature_len);
#endif
  base64(signature_value, 
         signature_value_len, 
         otp_b64_signature, 
         &otp_b64_signature_len);

  fprintf(stderr, "\nSignature Value is %s\n", otp_b64_signature);
  otp_get_subject_certificate(&subject,
                              &subject_len,
                              &certificate,
                              &certificate_len);

  /*Create the Final signed xml*/ 
  (*signed_xml) = (uint8_t *)malloc(10000000);
  assert((*signed_xml) != NULL);
  memset((void *)(*signed_xml), 0, 10000000);

  otp_compose_final_xml(*signed_xml, 
                        10000000, 
                        signed_xml_len,
                        /*digest*/
                        otp_b64,
                        /*Signature Value*/
                        otp_b64_signature,
                        /*Subject Name*/
                        subject,
                        /*Certificate*/
                        certificate); 

  free(signature_value);
  signature_value = NULL;
  free(subject);
  free(certificate);

  return(0);
}/*otp_sign_xml*/


/**
 * We use the SHA-1 message digest function, which outputs a hash value 20 bytes long
 */

int32_t otp_compute_digest(uint8_t *otp_xml, 
                           uint16_t otp_xml_len, 
                           uint8_t *digest,
                           uint32_t *digest_len) {

  EVP_MD_CTX *ctx;

  if((ctx = EVP_MD_CTX_create()) == NULL) {
    fprintf(stderr, "\n%s:%d Context creation failed\n", __FILE__, __LINE__);
    return(-1);
  }

  if(1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL)){
    fprintf(stderr, "\n%s:%d Init Failed\n", __FILE__, __LINE__);
    return(-2);
  }

  if(1 != EVP_DigestUpdate(ctx, otp_xml, otp_xml_len)) {
    fprintf(stderr, "\n%s:%d Update Failed\n", __FILE__, __LINE__);
    return(-3);
  }

  if(1 != EVP_DigestFinal_ex(ctx, digest, digest_len)) {
    fprintf(stderr, "\n%s:%d Final Failed\n", __FILE__, __LINE__);
    return(-5);
  }

  EVP_MD_CTX_destroy(ctx);
  ctx = NULL;

  return(0);
}/*otp_compute_digest*/ 

int32_t otp_compute_b64(uint8_t *sha1, 
                        uint16_t sha1_len, 
                        uint8_t *b64, 
                        uint16_t *b64_len) {

  uint16_t offset;
  uint16_t idx = 0;
  uint32_t tmp = 0;
  uint8_t *tmp_b64;
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


  tmp_b64 = (uint8_t *)malloc(idx + 64);
  uint16_t index = 0;

  for(offset = 0; index < idx; offset++) {
    if((offset > 0) && !(offset % 64)) {
      tmp_b64[offset] = '\n';
    } else {
      tmp_b64[offset] = b64[index++];
    }
  }

  *b64_len = offset;
  memcpy((void *)b64, tmp_b64, offset);
  return (0);
}/*otp_compute_b64*/

  
int32_t otp_compose_final_xml(uint8_t *out_xml, 
                              uint32_t out_xml_max_size, 
                              uint16_t *out_xml_len,
                              uint8_t *digest_b64,
                              uint8_t *signature_b64,
                              uint8_t *subject,
                              uint8_t *certificate) {

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
                 "%s%s%s%s",
                 "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n",
                 "      <SignedInfo>\n",
                 "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n",
                 "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n",
                 "      <Reference URI=\"\">\n",
                 "        <Transforms>\n",
                 "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n",
                 "        </Transforms>\n",
                 "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n",
                 "        <DigestValue>",
                 digest_b64,
                 "</DigestValue>\n",
                 "      </Reference>\n",
                 "      </SignedInfo>\n",
                 "      <SignatureValue>",
                 signature_b64,
                 "</SignatureValue>\n",
                 "      <KeyInfo>\n",
                 "        <X509Data>\n",
                 "          <X509SubjectName>",
                 subject,
                 "</X509SubjectName>\n",
                 "          <X509Certificate>",
                 certificate,
                 "</X509Certificate>\n",
                 "        </X509Data>\n",
                 "      </KeyInfo>\n",
                 "</Signature>",
                 "</Otp>");

  *out_xml_len = ret + otp_xml_len;

  //fprintf(stderr, "\nout_xml\n%s", out_xml);
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
                 "%s%s%.2d%s",
                 "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
                 "<Otp xmlns=\"http://www.uidai.gov.in/authentication/otp/1.0\" ac=\"public\"",
                 " lk=\"",
                 pOtpCtx->lk,
                 "\" sa=\"",
                 pOtpCtx->sa,
                 "\" tid=\"public\"",
                 " txn=\"",
                 pOtpCtx->txn,
                 "\" type=\"",
                 pOtpCtx->type,
                 "\" uid=\"",
                 pOtpCtx->uid,
                 "\" ver=\"",
                 /*It's value shall be 1.6*/
                 pOtpCtx->ver,
                 /*Otp attribute ends here*/
                 "\">\n",
                 /*otps tag starts*/
                 "  <Opts ch=\"",
                 pOtpCtx->ch,
                 "\"/>\n");

  *otp_xml_len = ret;

  return(0);
}/*otp_compose_otp_xml*/

int32_t otp_request_otp(uint8_t *signed_xml, 
                        uint16_t signed_xml_len, 
                        uint8_t **http_req, 
                        uint32_t *http_req_len) {

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
                 "%s%s%c%s%c"
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
                 "\r\n\r\n");

  memcpy((void *)&req_ptr[ret], signed_xml, signed_xml_len);
  req_max_len = ret + signed_xml_len;
  *http_req = req_ptr;
  *http_req_len = req_max_len;

  return(0); 
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

int32_t otp_send(int32_t conn_fd, 
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

  memset((void *)ip_str, 0, sizeof(ip_str));
  if(!(he = gethostbyname(hostname))) {
    // get the host info
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
  uidai_addr.sin_port = htons(pOtpCtx->uidai_port);

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

  pOtpCtx->otp_fd = fd;

  return (0);
}/*otp_connect_uidai*/

int32_t otp_process_otp_req(uint8_t *uid, int32_t conn_id) {

  otp_ctx_t *pOtpCtx = &otp_ctx_g;
  uint8_t *req_ptr = NULL;
  uint16_t req_len = 0;
  uint8_t *http_req = NULL;
  uint32_t http_req_len = 0;

  strncpy(pOtpCtx->uid, uid, strlen((const char *)uid));
  snprintf(pOtpCtx->txn,
           sizeof(pOtpCtx->txn),
           "%dSampleClient",
           conn_id);

  otp_sign_xml(&req_ptr, &req_len);
  otp_request_otp(req_ptr, 
                  req_len,
                  &http_req, 
                  &http_req_len);

  if(pOtpCtx->otp_fd < 0) {
    otp_connect_uidai(pOtpCtx->uidai_host_name);
  }

  fprintf(stderr, "\n%s:%d Req XML \n%s\n Length %d",
                  __FILE__,
                  __LINE__,
                  http_req,
                  http_req_len);
  
  otp_send(pOtpCtx->otp_fd, http_req, http_req_len);

  free(req_ptr);
  free(http_req);
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
    memset((void *)uid, 0, sizeof(uid));
    sscanf((const char *)packet_ptr, 
           "%*[^?]?%*[^&]&uid=%s", 
           uid);
    fprintf(stderr, "\n%s:%d uid %s\n", __FILE__, __LINE__, uid);
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
 *              https://www.di-mgt.com.au/xmldsig.html
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

int32_t main(int32_t argc, char *argv[]) {

  uint8_t buffer[1500];
  uint16_t buffer_len;
  uint8_t *ip_str = "172.20.10.7";
  uint8_t ip[4];
  uint32_t ip_addr;
  otp_ctx_t *pOtpCtx = &otp_ctx_g;

  sscanf(ip_str, "%d.%d.%d.%d", 
                 (int32_t *)&ip[0], 
                 (int32_t *)&ip[1], 
                 (int32_t *)&ip[2], 
                 (int32_t *)&ip[3]);

  ip_addr = ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3];

  otp_init("public",
           "public",
           "MG41KIrkk5moCkcO8w-2fc01-P7I5S-6X2-X7luVcDgZyOa2LXs3ELI",
           "Staging_Signature_PrivateKey.p12",
           "uidai_auth_stage.cer",
           ip_addr,
           8080,
           "developer.uidai.gov.in");

  memset((void *)buffer, 0, sizeof(buffer));
  buffer_len = snprintf(buffer, 
                        sizeof(buffer),
                        "%s",
                        "/request?type=otp&uid=999999990019");

  otp_process_nas_req(8, buffer, buffer_len);

  memset((void *)buffer, 0, sizeof(buffer));
  buffer_len = sizeof(buffer);

  otp_recv(pOtpCtx->otp_fd, buffer, &buffer_len);

  if(buffer_len > 0) {
    fprintf(stderr, "\n%s:%d ==> %s\n",
                    __FILE__,
                    __LINE__,
                    buffer);
  }
}/*main*/
#endif /* __OTP_C__ */
