#ifndef __SUBSCRIBER_C__
#define __SUBSCRIBER_C__

#include <type.h>
#include <common.h>


#define DD_S_SUBSCRIBER_AUTH_TABLE "conn_auth_status"

/********************************************************************
 *Extern Declaration
 *
 ********************************************************************/
extern uint32_t utility_ip_int_to_str(uint32_t ip_addr, uint8_t *ip_str);

extern uint32_t utility_mac_int_to_str(uint8_t *mac_addr, uint8_t *mac_str);

extern int db_process_query_result(int32_t *row_count, 
                                   int32_t *column_count, 
                                   char ***result);

extern int db_exec_query(uint8_t *sql_query);

/********************************************************************
 *Function Definitions
 *
 ********************************************************************/
int32_t subscriber_is_authenticated(uint32_t subscriber_ip) { 

  uint8_t ip_str[32];
  uint8_t mac_str[64];
  uint8_t sql_query[255];
  uint8_t record[2][16][32];
  uint32_t row = 0;
  uint32_t col = 0;  

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(subscriber_ip, ip_str);


#if 0
  snprintf((char *)sql_query, 
           sizeof(sql_query), 
           "%s%s%s%s%s"
           "%s",
           "SELECT * FROM ",
           DD_S_SUBSCRIBER_AUTH_TABLE,
           " WHERE (ip_address ='",
           ip_str,
           "' AND ( auth_state ='",
           "INPROGRESS' OR auth_state ='SUCCESS'))");
#endif
  snprintf((char *)sql_query, 
           sizeof(sql_query), 
           "%s%s%s%s%s",
           "SELECT * FROM ",
           DD_S_SUBSCRIBER_AUTH_TABLE,
           " WHERE ip_address ='",
           ip_str,
           "'");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, 2*16*32);

    if(!db_process_query_result(&row, &col, (char ***)record)) {
      if(row) {

        if(!strncmp((const char *)record[0][4], "INPROGRESS", 10)) {
          return(1);

        } else {
          /*SUCCESS*/
          return(2);
        }
      } 
    }    
  }
  return(0);
 
}/*subscriber_is_authenticated*/

int32_t subscriber_add_subscriber(uint32_t ip_address, 
                                  uint8_t *src_mac_ptr, 
                                  uint16_t src_port) {

  uint8_t sql_query[255];
  uint8_t ip_str[32];
  uint8_t mac_str[32];

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(ip_address, ip_str);
 
  memset((void *)mac_str, 0, sizeof(mac_str));
  utility_mac_int_to_str(src_mac_ptr, mac_str);

  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%s%s%d%s",
           "INSERT INTO ",
           DD_S_SUBSCRIBER_AUTH_TABLE,
           " (ip_address, mac_address, uri, host_name, auth_state, src_port) VALUES ('",
           ip_str,
           "', '", 
           mac_str,
           "', '', '', 'INPROGRESS', '",
           src_port,
           "')");

  if(db_exec_query(sql_query)) {
   fprintf(stderr, "\n%s:%d Execution of SQL Query Failed (%s)", __FILE__, __LINE__, sql_query);
   return(-1);
  }

}


int32_t subscriber_add_info(uint32_t ip_address,
                            uint16_t dest_port,
                            uint8_t *uri,
                            uint8_t *auth_state) {

  uint8_t sql_query[255];
  uint8_t ip_str[32];

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(ip_address, ip_str);
 
  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%d%s%s%s%s"
           "%s",
           "INSERT INTO ",
           DD_S_SUBSCRIBER_AUTH_TABLE,
           " (ip_address, dest_port, uri, auth_state) VALUES ('",
           ip_str,
           "', '", 
           dest_port,
           "', '",
           uri,
           "', '",
           auth_state,
           "')");

  if(db_exec_query(sql_query)) {
   fprintf(stderr, "\n%s:%d Execution of SQL Query Failed (%s)", __FILE__, __LINE__, sql_query);
   return(-1);
  }
  return(0);

}/*subscriber_add_info*/


int32_t subscriber_get_auth_state(uint32_t ip_address, 
                                  uint8_t *auth_state) {

  uint8_t sql_query[255];
  uint8_t ip_str[32];
  uint32_t row;
  uint32_t col;
  uint8_t record[2][16][32];

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(ip_address, ip_str);
 
  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s",
           "SELECT * FROM ",
           DD_S_SUBSCRIBER_AUTH_TABLE,
           " WHERE ip_address='",
           ip_str,
           "'");

  if(!db_exec_query(sql_query)) {
    memset((void *)record, 0, 2*16*32);
    if(!db_process_query_result(&row, &col, (char ***)record)) {
      if(row) {
        strncpy(auth_state, record[0][3], strlen((const char *)record[0][3]));
        return(0);
      }
    }
  }
  return(-1);
 
}/*subscriber_get_auth_state*/


int32_t subscriber_update_auth_state(uint32_t ip_address, 
                                     uint8_t *auth_state) {

  uint8_t sql_query[255];
  uint8_t ip_str[32];

  memset((void *)ip_str, 0, sizeof(ip_str));
  utility_ip_int_to_str(ip_address, ip_str);
 
  memset((void *)sql_query, 0, sizeof(sql_query));

  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "%s%s%s%s%s"
           "%s%s",
           "UPDATE ",
           DD_S_SUBSCRIBER_AUTH_TABLE,
           " SET auth_state='",
           auth_state,
           "' WHERE ip_address='",
           ip_str,
           "'");

  if(db_exec_query(sql_query)) {
   fprintf(stderr, "\n%s:%d Execution of SQL Query Failed (%s)", __FILE__, __LINE__, sql_query);
   return(-1);
  }
  return(0);
 
}/*subscriber_update_auth_state*/



#endif /* __SUBSCRIBER_C__ */
