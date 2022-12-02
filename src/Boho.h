/*
  Boho.h
  Ultra Light SSL Without RSA.
  Dongeun Lee <sixgen@gmail.com>
*/
#ifndef Boho_h
#define Boho_h

#include <SHA256.h>
#include <Crypto.h>

// USE_PSRAM: If you need large size memory on ESP boards which has PSRAM.
// #define USE_PSRAM    

#define MetaSize_AUTH_REQ 2
#define MetaSize_AUTH_NONCE 13
#define MetaSize_AUTH_HMAC 45
#define MetaSize_AUTH_ACK 33
#define MetaSize_ENC_PACK 25
#define MetaSize_ENC_488 21


union u32buf4{  uint32_t u32;  uint8_t buf[4]; };  // Union: uint32 & 4bytes buffer
union u16buf2{  uint16_t u16;  uint8_t buf[2]; };  // Union: uint16 & 2bytes buffer

// simple serial print debugger
void boho_print_time( uint32_t secTime );
void boho_print_hex( const void* titleStr, const void* data, size_t len);
void boho_index_print_hex( int num , char* titleStr, uint8_t* data, size_t len);
void boho_convert_hex( char* out, const void* data, size_t len);


/*
    Boho Authentication Process.
    client <<-AUTH_PACK->> server
    1. auth_req() 
      AUTH_REQ >>
    2. auth_nonce() //server send server nonce
      << AUTH_NONCE or AUTH_FAIL
    3. auth_hmac( buffer) //client send  hmac with server nonce
      AUTH_HMAC >>
    4. check_auth_hmac( infoPack)  //server verify client.
      AUTH_ACK <<
    5. check_auth_ack_hmac( buffer)  //client verify server.
*/

class Boho
{
  public:
    enum MsgType : uint8_t{
      AUTH_REQ = 0xB0,
      AUTH_NONCE,
      AUTH_HMAC,
      AUTH_ACK,
      AUTH_FAIL,
      AUTH_EXT,
      ENC_PACK, 
      ENC_E2E,  
      ENC_488,   
    };


    Boho( void);
    void set_id8(const char* data );
    void set_hash_id8(const char* data );
    void set_hash_id8(const void* data, size_t len );

    void set_key(const char* data );
    void set_key(const void* data, size_t len );

    void setTime( uint32_t utc );
    void refreshTime( void );
    uint32_t getUnixTime();

    void set_salt12(const void *salt12 );
    void set_clock_rand( void);
    void set_clock_nonce( const void* nonce);

    void resetOTP(void);
    void generateIndexOTP( uint8_t* iotp, uint32_t otpIndex );

    bool generateHMAC( const void* data, uint32_t dataLen );

    void xotp( uint8_t* data, uint32_t len );
    void setHash( void* result, const void* data, size_t len);

    uint32_t encryptPack( uint8_t *out, const void *in, uint32_t len );
    uint32_t decryptPack(  void *out, uint8_t *in, uint32_t len );

    uint32_t encrypt_e2e( uint8_t *out, const void *in, uint32_t len , const char * key);
    uint32_t decrypt_e2e(  void *out, uint8_t *in, uint32_t len , const char * key);

    int login();
    int auth_req( uint8_t* out);
    int auth_hmac( uint8_t* out, const void* auth_req , size_t len);
    bool check_auth_ack_hmac( const void* auth_ack, size_t len );

    uint32_t encrypt_488( uint8_t *out, const void *in, uint32_t len );
    uint32_t decrypt_488( void *out, uint8_t *in, uint32_t len );
    
    bool isAuthorized = false;
    uint8_t _otpSrc44[44]={0};  // mainKey[32]+ otpSrcPublic[12]

  private:
    Hash *hash;
    uint8_t _id8[8]={0};
    uint8_t _otp36[36]={0};
    uint8_t _hmac[32];
    
    union u32buf4 secTime, milTime , microTime;
    union u32buf4 remoteNonce , localNonce;
    uint32_t  lastSetMilTime; 
};




#endif


