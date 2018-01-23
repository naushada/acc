
    memset((void *)record, 0, sizeof(record));
    /*Query is executed successfully*/
    if(db_process_query_result(&row, &col, (uint8_t (*)[16][32])record)) {
      fprintf(stderr, "\nprocess query result is failed");
      exit(0);
    }

    if(row > 0) {
      /*Requested IP address can be allocated, proceed to it*/

       memset((void *)host_name, 0, sizeof(host_name));
       dhcp_get_dhclient_host_name(host_name);

      /*Update the xid received from dhcp client*/
      memset((void *)sql_query, 0, sizeof(sql_query));
      snprintf((char *)sql_query,
               sizeof(sql_query),
               "%s%s%s%s%s"
               "%s%s%s%d%s",
               "UPDATE ",
               pDhcpCtx->acc_ip_allocation_table_name,
               " SET ",
               "host_name='",
               host_name,
               "',ip_allocation_status='ASSIGNED' WHERE (network_id ='",
               ip_str,
               "' AND host_id ='",
               host_id,
               "')");

      if(db_exec_query((char *)sql_query)) {
        fprintf(stderr, "\nExecution of SQL query failed");
        exit(0);
      }
      return(1);
    }
  }

  /*Requested IP address can not be allocated*/
  return(0);
}/*dhcp_is_dhcpc_requested_ip*/

/** @brief This function allocates the IP address to dhclient, If IP is already
 *         allocated then provide it to dhclient else allocate the free ip for dhclient.
 *
 *  @param mac_addr is the mac address of the client
 *  @return allocated ip address
 */
uint32_t dhcp_get_client_ip(uint8_t *mac_addr) {

  char sql_query[512];
  uint8_t record[2][16][32];
  int  row = 0;
  int  col = 0;
  uint32_t ip_addr;
  uint8_t mac_str[32];
  uint8_t ip_str[32];
  uint8_t host_name[255];
                                                                                                                                                                                          982,4         76%

