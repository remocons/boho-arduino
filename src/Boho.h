/*
 * Boho.h — Cryptography Module
 * 
 * - Data encryption
 * - Encrypted Client–Server Authentication
 * - Secure communication
 *
 * Author: Taeo Lee <sixgen@gmail.com>
 */

#ifndef Boho_h
#define Boho_h

#include "Arduino.h"
#include <SHA256.h>
#include <Crypto.h>
#include <string.h>
#if defined(ESP32)
  #include "esp_heap_caps.h"
  #include "esp32-hal-psram.h"
#endif

#define MetaSize_SERVER_TIME_NONCE 13
#define MetaSize_AUTH_REQ 45
#define MetaSize_AUTH_RES 33
#define MetaSize_ENC_PACK 25
#define MetaSize_ENC_488 21

union u32buf4{  uint32_t u32;  uint8_t buf[4]; };  // Union: uint32 & 4bytes buffer
union u16buf2{  uint16_t u16;  uint8_t buf[2]; };  // Union: uint16 & 2bytes buffer

// simple serial print debugger
void boho_print_time( uint32_t secTime, uint16_t ms = 0 );
void boho_print_hex( const void* titleStr, const void* data, size_t len);
void boho_index_print_hex( int num , char* titleStr, uint8_t* data, size_t len);
void boho_convert_hex( char* out, const void* data, size_t len);

void* dynamic_alloc(size_t size);

class Boho
{
  public:
    enum MsgType : uint8_t{
      SERVER_TIME_NONCE = 0xB0,
      AUTH_REQ,
      AUTH_RES,
      AUTH_FAIL,
      ENC_PACK = 0xB6, 
      ENC_E2E,  
      ENC_488,   
    };

    Boho( void);
    void clearAuth(void);
    void set_id8(const char* data );
    void set_hash_id8(const char* data );
    void set_hash_id8(const void* data, size_t len );

    void set_key(const char* data );
    void set_key(const void* data, size_t len );
    void set_id_key(const char* id_key );

    void setTime( uint32_t utc, uint16_t ms = 0);
    void setClientTimeToServerTime( const uint8_t* server_time_nonce , size_t len);
    void refreshTime( void );
    uint32_t getUnixTime();
    uint16_t getMilTime();

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
    uint32_t encrypt_488( uint8_t *out, const void *in, uint32_t len );
    uint32_t decrypt_488( void *out, uint8_t *in, uint32_t len );

    int auth_req( uint8_t* );
    int auth_req( uint8_t* out, const uint8_t* server_time_nonce , size_t len);
    bool verify_auth_res( const uint8_t* auth_res, size_t len );

    bool isAuthorized = false;

  private:
    Hash *hash;
    uint8_t _id8[8]={0};
    uint8_t _otpSrc44[44]={0};  // mainKey[32]+ otpSrcPublic[12]
    uint8_t _otp36[36]={0};
    uint8_t _hmac[32];
    union u32buf4 remoteNonce , localNonce;
    union u32buf4 secTime , microTime;
    union u16buf2 milTime;
    union u16buf2 counter;
    uint32_t lastTime;
    
};

#endif


