#ifndef __VERIFY_H__
#define __VERIFY_H__

typedef struct {
  uint8_t session_key[32];
  uint8_t iv[16];
  uint8_t aad[18];

}verify_ctx_t;


int32_t verify_read_xml(uint8_t *xml_data, uint32_t *xml_data_len);

int32_t verify_parse_xml(uint8_t *xml_data, uint8_t (*parsed_tag)[1024]);

int32_t verify_get_skey(uint8_t *b64_skey, uint32_t b64_skey_len, uint8_t *skey);

int32_t verify_main(void);














#endif /* __VERIFY_H__ */
