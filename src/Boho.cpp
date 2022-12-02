
/*
  Boho.cpp
  Ultra Light SSL Without RSA.
  Dongeun Lee <sixgen@gmail.com>
*/
#include "Boho.h"
#include "Arduino.h"
#include <SHA256.h>
#include <Crypto.h>
#include <string.h>

Boho::Boho()
{
  hash = new SHA256();
  secTime.u32 = 0;
  milTime.u32 = 0;
  microTime.u32 = 0;
  remoteNonce.u32 = 0;
  localNonce.u32 = 0;
  lastSetMilTime = millis();
}

// accept max 8 chars.
void Boho::set_id8(const char* data )
{
  int len = strlen(data) ;
  if( len > 8 ) len = 8;
  memcpy( _id8 , data, len);
}

void Boho::set_hash_id8(const char* data )
{
  set_hash_id8( data, strlen(data));
}

void Boho::set_hash_id8(const void* data, size_t len)
{
  uint8_t idSum[32];
  hash->reset();
  hash->update( data, len);
  hash->finalize( idSum, 32);
  memcpy( _id8 , idSum, 8);
}

void Boho::set_key(const char*data )
{
  set_key( data, strlen(data));
}

void Boho::set_key(const void* data, size_t len )
{
  hash->reset();
  hash->update( data, len);
  hash->finalize( _otpSrc44, 32);
}


void  Boho::setTime( uint32_t utc ){
  secTime.u32 = utc;
  milTime.u32 = 0;
  lastSetMilTime = millis();
}

// refresh internal time.
void  Boho::refreshTime( void){
      uint32_t milNow = millis();
      uint32_t delta;

      if( milNow == lastSetMilTime ){ 
        //too short period refresh
        return;
      }else if( milNow > lastSetMilTime ){
        delta = milNow - lastSetMilTime; 
      }else{ 
        // overflow: period is about 49 days 17 hours.
        delta = milNow + (0xffffffff - lastSetMilTime) ;
      }
      lastSetMilTime = milNow;

      // // deltaSec delteMil
      delta += milTime.u32; 
      secTime.u32 += (uint32_t)( (float)delta / 1000);  
      milTime.u32 = delta % 1000;

  }

uint32_t Boho::getUnixTime()
{
  return secTime.u32;
}

void Boho::setHash( void* result, const void* data, size_t len)
{
  hash->reset();
  hash->update( data, len);
  hash->finalize( result, 32);
}


bool Boho::generateHMAC(  const void* data, uint32_t dataLen )
{

  uint8_t *tmp = NULL;

  #ifdef USE_PSRAM
    tmp = (uint8_t *)ps_malloc( dataLen + 44);
  #else
    tmp = (uint8_t *)malloc( dataLen + 44);
  #endif
  if( tmp == NULL ) return false;

  memcpy( tmp , _otpSrc44 , 44 ); // mainKey area
  memcpy( tmp + 44 , data , dataLen );
  setHash( _hmac , tmp, 44 + dataLen );
  free(tmp);
  return true;
}



void Boho::set_salt12( const void* data )
{
  memcpy( _otpSrc44 + 32, data , 12);
}

void Boho::set_clock_rand( void)
{
  refreshTime();
  microTime.u32 = micros();  
  memcpy( _otpSrc44 + 32, secTime.buf , 4);
  memcpy( _otpSrc44 + 36, milTime.buf , 4);
  memcpy( _otpSrc44 + 40, microTime.buf  , 4);
}


void Boho::set_clock_nonce( const void* nonce)
{
  refreshTime();
  memcpy( _otpSrc44 + 32, secTime.buf , 4);
  memcpy( _otpSrc44 + 36, milTime.buf , 4);
  memcpy( _otpSrc44 + 40, nonce  , 4);
}

void Boho::resetOTP( void)
{
  setHash(_otp36, _otpSrc44, 44 );

}

void Boho::generateIndexOTP( uint8_t* iotp, uint32_t otpIndex )
{
  u32buf4 u32Len;
  u32Len.u32 = otpIndex;
  memcpy( _otp36 + 32 , u32Len.buf, 4 );
  setHash(iotp, _otp36, 36);
}




void Boho::xotp( uint8_t* data, uint32_t dataLen  )
{
  int len = dataLen;
  uint32_t otpIndex = 0;
  
  int dataOffset = 0;
  int xorCalcLen = 0;

  uint8_t iotp[32];
    
  while( len > 0 ){
    xorCalcLen = len < 32 ? len : 32;
    generateIndexOTP(iotp, ++otpIndex );
   
    for(int i = 0; i< xorCalcLen; i++){
      data[dataOffset++] ^= iotp[i];
    }
    len -= 32;
  }

}



uint32_t Boho::encryptPack( uint8_t *output, const void *input, uint32_t inputLen )
{

  set_clock_rand();
  resetOTP();

  if( !generateHMAC( input, inputLen ) ) return 0;
  
  memcpy( output + MetaSize_ENC_PACK , input , inputLen);
  xotp( (uint8_t *)(output + MetaSize_ENC_PACK), inputLen );
  output[0] = Boho::MsgType::ENC_PACK;

  u32buf4 dLen ;
  dLen.u32 = inputLen;
  memcpy( output + 1 , dLen.buf, 4 );
  memcpy( output + 5 , _otpSrc44 + 32 , 12 ); 
  memcpy( output + 17 , _hmac , 8 ); 
  return inputLen + MetaSize_ENC_PACK;

}


uint32_t Boho::decryptPack(  void *output, uint8_t *input, uint32_t inputLen )
{

  if( input[0] != Boho::MsgType::ENC_PACK ){
    // Serial.print("#Invalid msgType: ");
    return 0;
  }

  u32buf4 dLen;
  memcpy( dLen.buf, input + 1, 4 );
  int payloadSize = dLen.u32;
  if( payloadSize != inputLen - MetaSize_ENC_PACK ){
    // Serial.print("#Invalid size: ");
    return 0; 
  }

  set_salt12( input + 5 );   // salt begin.  // 3->5
  resetOTP();

  memcpy( output, input + MetaSize_ENC_PACK , payloadSize);
  xotp( (uint8_t *)output, payloadSize );

  
  if( !generateHMAC( output , payloadSize) ) return 0;

  if( memcmp(_hmac, input + 17 , 8) != 0 ){  
    // Serial.print("#Invalid HMAC: ");
    return 0;
  }
  
  return payloadSize;
}

uint32_t Boho::encrypt_e2e( uint8_t *output, const void *input, uint32_t inputLen , const char * key )
{

  // backup base key
  uint8_t authKeyBackup[32];
  memcpy( authKeyBackup, _otpSrc44, 32);

  // set temporary key.
  set_key( key);

  uint32_t packSize = encryptPack( output, input, inputLen );

  // restore base key
  memcpy( _otpSrc44,  authKeyBackup, 32);
  
  return packSize;

}


uint32_t Boho::decrypt_e2e(  void *output, uint8_t *input, uint32_t inputLen , const char * key )
{

  if( input[0] != Boho::MsgType::ENC_PACK ){
    return 0;
  }

  // backup base key
  uint8_t authKeyBackup[32];
  memcpy( authKeyBackup, _otpSrc44, 32);
  
  // set temporary key.
  set_key( key);

  uint32_t packSize = decryptPack( output, input, inputLen );
  
  // restore base key
  memcpy( _otpSrc44,  authKeyBackup, 32); 
  return packSize;
}


uint32_t Boho::encrypt_488( uint8_t *output, const void *input, uint32_t inputLen )
{
  if( !isAuthorized ) return 0;

  set_clock_nonce( remoteNonce.buf );
  resetOTP();
  
  if( !generateHMAC( input, inputLen ) ) return 0;

  memcpy( output + MetaSize_ENC_488 , input , inputLen  );
  xotp( (uint8_t *)(output + MetaSize_ENC_488 ), inputLen );

  output[0] = Boho::MsgType::ENC_488;

  u32buf4 dLen ;
  dLen.u32 = inputLen;
  memcpy( output + 1 , dLen.buf, 4 );

  memcpy( output + 5 , _otpSrc44 + 32 , 8 ); 
  memcpy( output + 13 , _hmac , 8 ); 
  
  return inputLen + MetaSize_ENC_488;

}


/*
  byte_index:name
  0:type
  1,2,3,4: payloadlen
  5: otpSrc8
  13: hmac8
  21: payload
*/

uint32_t Boho::decrypt_488(void *output, uint8_t *input,  uint32_t inputLen )
{
  if( !isAuthorized ) return 0;
  
  u32buf4 pLen;
  memcpy( pLen.buf, input+1, 4);
  uint32_t payloadSize = pLen.u32;

  // uint32_t payloadSize = input[1] + ( input[2] << 8 )  + ( input[3] << 16 )  + ( input[4] << 24 );
  if( payloadSize > inputLen - MetaSize_ENC_488 ){
    return 0; 
  }

  //set salt:  from retmote 8, localNonce 4
  memcpy( _otpSrc44 + 32 , input + 5 , 8 );   // 3->5
  memcpy( _otpSrc44 + 40 , localNonce.buf , 4 );
  
  resetOTP();

  memcpy( output, input + MetaSize_ENC_488 , payloadSize);  // 19 -> 21
  xotp( (uint8_t *)output, payloadSize );
  
  if( !generateHMAC( output , payloadSize) ) return 0;

  if( memcmp(_hmac, input + 13 , 8) != 0 ){  // 11->13
    // Serial.print("#Invalid hmac.");
    return 0;
  }
  
  return payloadSize;
}


// 1. client send AUTH_REQ
int Boho::auth_req( uint8_t* out )
{
  out[0] = Boho::MsgType::AUTH_REQ;
  out[1] = 0; //reserved
  return 2;
}

// 2. server send AUTH_NONCE. (include server unix time.)

// 3 client
//  reveive AUTH_NONCE.
//  store server nonce.( include unix time. )
//  generate auth_hmac.
//  send AUTH_HMAC packet.
int Boho::auth_hmac( uint8_t* output, const void* auth_nonce , size_t inputLen )
{

 if( inputLen != MetaSize_AUTH_NONCE ) return 0;

  memcpy( secTime.buf, auth_nonce + 1 , 4);
  memcpy( milTime.buf, auth_nonce + 5 , 4);
  lastSetMilTime = millis(); // MUST : reset after change time.

  memcpy( remoteNonce.buf, auth_nonce + 9 , 4);

  set_salt12( auth_nonce + 1 ); //read 12bytes from auth_nonce
  localNonce.u32 = micros(); //generate localNonce
  
  if( !generateHMAC( localNonce.buf, 4 ) ) return 0;

  output[0] = Boho::MsgType::AUTH_HMAC;
  
  memcpy( output + 1 , _id8 , 8); 
  memcpy( output + 9, localNonce.buf, 4 ); 
  memcpy( output + 13 , _hmac , 32 );    
  
  return MetaSize_AUTH_HMAC; 
}

// 4. 
// server check client hmac
// server send  AUTH_ACK or AUTH_FAIL

// 5. client check server AUTH_ACK (cross check.)
bool Boho::check_auth_ack_hmac( const void* auth_ack, size_t inputLen )
{
   if( inputLen != MetaSize_AUTH_ACK ) return false;

  uint8_t hmacSrc[12];
  memcpy( hmacSrc, remoteNonce.buf , 4);
  memcpy( hmacSrc + 4 , localNonce.buf , 4);
  memcpy( hmacSrc + 8, remoteNonce.buf , 4);

  set_salt12( hmacSrc ); 
  if( !generateHMAC( localNonce.buf , 4 )) return false;

  if( memcmp(_hmac, auth_ack + 1 , 32 ) != 0 ){
    return false;
  }

  isAuthorized = true;
  return true;
}


// simple serial print debugger

void boho_print_time( uint32_t secTime ){
    secTime %= 86400; 
    uint32_t sec = secTime % 60;  
    secTime -= sec;  
    uint32_t min = secTime / 60 ;
    min %= 60;
    secTime -= ( min * 60 );
    uint32_t hour = secTime / 3600;
    char tmp[30]={0};
    sprintf( tmp, "[%02u:%02u:%02u]\n", ( uint8_t)hour, ( uint8_t) min, ( uint8_t)sec );
    Serial.write( tmp );
}


void boho_print_hex( const void* titleStr, const void* data, size_t len){
  Serial.write( (char* )titleStr);
  char tmp[6] = {0};
  sprintf(tmp , "[%u] ", len);
  Serial.write( tmp );  
  for(int i=0; i< len; ++i){
    sprintf(tmp, "%02x",  *( (uint8_t *)data + i));
    Serial.write(tmp);  
  }
  Serial.write("\n");
}


void boho_index_print_hex( int num , char* titleStr, uint8_t* data, size_t len){
  char tmp[6] = {0};
  sprintf(tmp , "#%u ", num); 
  Serial.write( tmp );  
  boho_print_hex( titleStr, data, len );
}

void boho_convert_hex( char* output, const void* input, size_t inputLen){
  for(int i=0; i< inputLen; i++){
    sprintf( output + i * 2, "%02x",  *((uint8_t* )input + i ) );
  }
}