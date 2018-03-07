#ifndef __VERIFY_C__
#define __VERIFY_C__

#include <type.h>
#include <stdio.h>
#include <string.h>
#include <util.h>

int32_t verify_read_xml(uint8_t *xml_data, uint32_t *xml_data_len) {
  int32_t rc;
  FILE *fp;
  uint32_t max_size = 5000;

  fp = fopen("Auth_xml.xml", "r");

  rc = fread(xml_data, 1, max_size, fp);

  if(rc > 0) {
    *xml_data_len = rc;
  } 

  return(0);
}/*verify_read_xml*/

int32_t verify_get_tag_value(uint8_t (*in)[1024], 
                             uint8_t *start_tag, 
                             uint8_t *end_tag, 
                             uint8_t *value) {
  uint32_t idx;
  uint32_t offset;
  uint8_t tag_start_f;
  uint8_t tag_end_f;
  uint8_t attr_f;

  if(!start_tag) {
    value = NULL;
    return(-1);
  }

  if(!end_tag) {
    value = NULL;
    return(-2);
  }

  for(idx = 0; in[idx][0]; idx++) {
    /*starting of tag*/
    if('<' == in[idx][0]) {
      tag_start_f = 1;

      for(offset = 0; start_tag[offset]; offset++) {
        /*compare the individual character*/
        if(in[idx][offset] != start_tag[offset]) {
          break;
        }
      }

      offset--;
      /*strlen returns length excluding '\0' character*/ 
      if(offset == strlen(start_tag)) {
        if('>' != start_tag[offset]) {
          
        }
      }
    }   
  }

}/*verify_get_tag_value*/

int32_t verify_parse_xml(uint8_t *xml_data, uint8_t (*parsed_tag)[1024]) {
  uint8_t *line_ptr = xml_data;
  uint8_t *tmp_ptr = NULL;
  uint32_t idx = 0;

  tmp_ptr = strtok(line_ptr, "\n");
  
  do {

    strncpy(parsed_tag[idx++], tmp_ptr, 1024);
  } while((tmp_ptr = strtok(NULL, "\n")));

  /*Make sure that last row is NULL terminated*/
  *((uint8_t *)&parsed_tag[idx][0]) = '\0';

  for(idx = 0; parsed_tag[idx][0]; idx++) {
    fprintf(stderr, "%s", parsed_tag[idx]);
  }
  return(0);
}/*verify_parse_xml*/

int32_t verify_get_skey(uint8_t *b64_skey, uint32_t b64_skey_len, uint8_t *skey) {
  uint8_t in[1024];
  uint32_t in_len;
  uint8_t octet[1024];
  uint8_t octet_len;
  uint32_t idx;

  memset((void *)octet, 0, sizeof(octet));
  memset((void *)in, 0, sizeof(in));

  //util_delete_newline(b64_skey, b64_skey_len, in, &in_len);
  //fprintf(stderr, "\n%s\n", b64_skey);
  /*Remove the start and end Skey tag*/
  sscanf(in, "%*[^>]>%s%*[^<]",octet);

  memset((void *)in, 0, sizeof(in));
  util_base64_decode(octet, strlen(octet), in, &in_len);
  octet_len = 0;
  util_decrypt_skey(in, in_len, skey, &octet_len);
  
  printf("\n");
  for(idx = 0; idx < octet_len; idx++) {
    fprintf(stderr, "%.2X ", skey[idx]);
  }
  printf("\n");

  return(0);
}/*verify_get_skey*/

int32_t verify_main(void) {
  uint8_t *xml;
  uint32_t xml_size;
  uint32_t xml_len;
  uint8_t parsed_arr[32][1024];
  uint32_t idx;
  uint8_t skey[32];

  xml_size = 5000;
  xml = (uint8_t *)malloc(xml_size);
  memset((void *)xml, 0, xml_size);
  /*Read the xml file*/
  verify_read_xml(xml, &xml_len);
  
  memset((void *)parsed_arr, 0, sizeof(parsed_arr));
  /*remove the \n and store each line into an array*/
  verify_parse_xml(xml, parsed_arr);

  memset((void *)xml, 0, xml_size);

  for(idx = 0; parsed_arr[idx]; idx++) {
    
    fprintf(stderr, "\nb64_skey %s\n", parsed_arr[idx]);
    if(!strncmp(parsed_arr[idx], "<Skey", 5)) {
      memset((void *)skey, 0, sizeof(skey));
      verify_get_skey(parsed_arr[idx], strlen(parsed_arr[idx]), skey);
      break;
    }
  }

  free(xml);
  printf("Plain skey\n");
  for(idx = 0; idx < 32; idx++) {
    fprintf(stderr, "%.2x ", skey[idx]);
  }

  printf("End Plain skey\n");
}/*verify_main*/
#endif /* __VERIFY_C__ */
