#ifndef __OAUTH20_H__
#define __OAUTH20_H__

#define CLIENT_ID  "412727589579-uln740n6b2pqonc56n71lmc098aq7kqd.apps.googleusercontent.com"


typedef struct {
  /*google host name- www.accounts.google.com*/
  uint8_t host_name[64];
  /*random number encoded in base64 form*/
  uint8_t state[64];
  /*scope could be profile, email or openid*/
  uint8_t scope[16];
  /*once user is logged in, google will redirect user to this url*/
  uint8_t redirect_uri[128];
  
}oauth20_ctx_t;






#endif /* __OAUTH20_H__ */
