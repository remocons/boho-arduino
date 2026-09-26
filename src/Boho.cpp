/*
 * Boho.cpp — Cryptography Module
 * 
 * - Data encryption
 * - Encrypted Client–Server Authentication
 * - Secure communication
 *
 * Author: Taeo Lee <sixgen@gmail.com>
 */

#if defined(ESP32)
  #include "esp_heap_caps.h"
  #include "esp32-hal-psram.h"
#endif

#include "Boho.h"

Boho::Boho()
{
  hash = new SHA256();
  secTime.u32 = 0;
  milTime.u16 = 0;
  counter.u16 = 0;
  microTime.u32 = 0;
  remoteNonce.u32 = 0;
  localNonce.u32 = 0;
  lastTime = millis();
}

void Boho::clearAuth(void)
{
  memset( _id8, 0, 8);
  memset( _otpSrc44, 0, 44);
  memset( _otp36, 0, 36);
  memset( _hmac, 0, 32);
  memset( localNonce.buf, 0, 4);
  memset( remoteNonce.buf, 0, 4);
  isAuthorized = false;
  hasKey = false;
  hasChallenge = false;
  memset(serverChallenge, 0, sizeof(serverChallenge));
}

// accept max 8 chars.
void Boho::set_id8(const char* data )
{
  memset(_id8, 0, sizeof(_id8));
  if (!data) return;
  size_t len = 0;
  while (len < sizeof(_id8) && data[len]) ++len;
  memcpy(_id8, data, len);
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
  set_key(data, data ? strlen(data) : 0);
}

void Boho::set_key(const void* data, size_t len )
{
  if (!data || !len) {
    memset(_otpSrc44, 0, sizeof(_otpSrc44));
    hasKey = false;
    isAuthorized = false;
    return;
  }
  hash->reset();
  hash->update(data, len);
  hash->finalize(_otpSrc44, 32);
  hasKey = true;
}

void Boho::set_id_key(const char* id_key )
{
  if (!id_key) { clearAuth(); return; }
  const char *dot = strchr(id_key, '.');
  if (!dot || dot == id_key || dot - id_key > 8 || !dot[1]) {
    clearAuth();
    return;
  }
  char id[9] = {0};
  memcpy(id, id_key, dot - id_key);
  set_id8(id);
  set_key(dot + 1);
}

void  Boho::refreshTime( void)
{
  const uint32_t now = millis();
  const uint32_t delta = now - lastTime; // unsigned subtraction includes rollover
  lastTime = now;
  ++counter.u16;
  // Split before adding the remainder to avoid a uint32_t overflow.
  secTime.u32 += delta / 1000;
  const uint16_t remainder = milTime.u16 + delta % 1000;
  secTime.u32 += remainder / 1000;
  milTime.u16 = remainder % 1000;
}

uint32_t Boho::getUnixTime()
{
  return secTime.u32;
}

uint16_t Boho::getMilTime()
{
  return milTime.u16;
}

void Boho::setHash( void* result, const void* data, size_t len)
{
  hash->reset();
  hash->update( data, len);
  hash->finalize( result, 32);
}

bool Boho::generateHMAC(  const void* data, uint32_t dataLen )
{
  if (!hasKey || (!data && dataLen) || dataLen > (uint32_t)((size_t)-1)) return false;
  hash->reset();
  hash->update(_otpSrc44, sizeof(_otpSrc44));
  if (dataLen) hash->update(data, (size_t)dataLen);
  hash->finalize(_hmac, sizeof(_hmac));
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
  memcpy( _otpSrc44 + 36, milTime.buf , 2);
  memcpy( _otpSrc44 + 38, counter.buf , 2);
  memcpy( _otpSrc44 + 40, microTime.buf  , 4);  // JS: use crypto.getRandomValues(),  Arduino: use micros()
}


void Boho::set_clock_nonce( const void* nonce)
{
  refreshTime();
  memcpy( _otpSrc44 + 32, secTime.buf , 4);
  memcpy( _otpSrc44 + 36, milTime.buf , 2);
  memcpy( _otpSrc44 + 38, counter.buf , 2);
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
  uint32_t otpIndex = 0;
  uint8_t iotp[32];
  while (dataLen) {
    const uint8_t count = dataLen < 32 ? dataLen : 32;
    generateIndexOTP(iotp, ++otpIndex);
    for (uint8_t i = 0; i < count; ++i) *data++ ^= iotp[i];
    dataLen -= count;
  }
}



uint32_t Boho::encryptPack( uint8_t *output, const void *input, uint32_t inputLen )
{
  if (!hasKey || !output || (!input && inputLen) || inputLen > (uint32_t)((size_t)-1) - MetaSize_ENC_PACK) return 0;


  set_clock_rand();
  resetOTP();

  if( !generateHMAC( input, inputLen ) ) return 0;
  
  if (inputLen) memmove(output + MetaSize_ENC_PACK, input, inputLen);
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
  uint32_t length = 0;
  decryptPack(output, input, inputLen, length);
  return length;
}

uint32_t Boho::encrypt_e2e( uint8_t *output, const void *input, uint32_t inputLen , const char * key )
{
  if (!key || !*key) return 0;
  uint8_t backup[32];
  memcpy(backup, _otpSrc44, 32);
  const bool previousKey = hasKey;
  set_key(key);
  const uint32_t size = encryptPack(output, input, inputLen);
  memcpy(_otpSrc44, backup, 32);
  hasKey = previousKey;
  memset(backup, 0, sizeof(backup));
  return size;
}


uint32_t Boho::decrypt_e2e(  void *output, uint8_t *input, uint32_t inputLen , const char * key )
{
  uint32_t length = 0;
  decrypt_e2e(output, input, inputLen, key, length);
  return length;
}


uint32_t Boho::encrypt_488( uint8_t *output, const void *input, uint32_t inputLen )
{
  if (!hasKey || !output || (!input && inputLen) || inputLen > (uint32_t)((size_t)-1) - MetaSize_ENC_488) return 0;

  if( !isAuthorized ) return 0;

  set_clock_nonce( remoteNonce.buf );
  resetOTP();
  
  if( !generateHMAC( input, inputLen ) ) return 0;

  if (inputLen) memmove(output + MetaSize_ENC_488, input, inputLen);
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
  uint32_t length = 0;
  decrypt_488(output, input, inputLen, length);
  return length;
}

void  Boho::setTime( uint32_t utc , uint16_t millis )
{
  secTime.u32 = utc + millis / 1000;
  milTime.u16 = millis % 1000;
  lastTime = ::millis();
}

void Boho::setClientTimeToServerTime( const uint8_t* server_time_nonce , size_t inputLen )
{
  if (!server_time_nonce || inputLen != MetaSize_SERVER_TIME_NONCE ||
      server_time_nonce[0] != SERVER_TIME_NONCE) return;
  u16buf2 ms;
  memcpy(ms.buf, server_time_nonce + 5, 2);
  if (ms.u16 >= 1000) return;
  if (server_time_nonce != serverChallenge) memcpy(serverChallenge, server_time_nonce, sizeof(serverChallenge));
  hasChallenge = true;
  memcpy(secTime.buf, server_time_nonce + 1, 4);
  milTime = ms;
  lastTime = millis();
}

int Boho::auth_req( uint8_t* output, const uint8_t* server_time_nonce , size_t inputLen )
{

  if (!hasKey || !output || !server_time_nonce || inputLen != MetaSize_SERVER_TIME_NONCE ||
     server_time_nonce[0] != SERVER_TIME_NONCE) return 0;
  u16buf2 ms;
  memcpy(ms.buf, server_time_nonce + 5, 2);
  if (ms.u16 >= 1000) return 0;
  if (server_time_nonce != serverChallenge) {
    setClientTimeToServerTime(server_time_nonce, inputLen);
    memcpy(counter.buf, server_time_nonce + 7, 2);
  }
  memcpy( remoteNonce.buf, server_time_nonce + 9 , 4);

  set_salt12( server_time_nonce + 1 ); //read 12bytes from server_time_nonce
  localNonce.u32 = micros();
  
  if( !generateHMAC( localNonce.buf, 4 ) ) return 0;

  output[0] = Boho::MsgType::AUTH_REQ;
  memcpy( output + 1 , _id8 , 8); 
  memcpy( output + 9, localNonce.buf, 4 ); 
  memcpy( output + 13 , _hmac , 32 );    
  
  return MetaSize_AUTH_REQ; 
}

bool Boho::verify_auth_res( const uint8_t* auth_ack, size_t inputLen )
{
  if (!hasKey || !hasChallenge || !auth_ack || inputLen != MetaSize_AUTH_RES || auth_ack[0] != AUTH_RES) return false;
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

void* dynamic_alloc(size_t size) {
  #if defined(ESP32)
    if (psramFound()) {
      return heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    } else {
      return malloc(size);
    }
  #else
    return malloc(size);
  #endif
}


// simple serial print debugger
void boho_print_time(uint32_t secTime, uint16_t ms)
{
    // Convert Unix time to HH:MM:SS
    secTime %= 86400;  // seconds in a day
    uint32_t sec = secTime % 60;
    uint32_t min = (secTime / 60) % 60;
    uint32_t hour = secTime / 3600;

    char tmp[40] = {0};
    // Include milliseconds (0~999)
    sprintf(tmp, "[%02u:%02u:%02u.%03u]\n",
            (uint8_t)hour,
            (uint8_t)min,
            (uint8_t)sec,
            (uint16_t)ms);

    Serial.write(tmp);
}

void boho_print_hex( const void* titleStr, const void* data, size_t len){
  Serial.write( (char* )titleStr);
  char tmp[24] = {0};
  snprintf(tmp, sizeof(tmp), "[%lu] ", (unsigned long)len);
  Serial.write( tmp );  
  for(int i=0; i< len; ++i){
    sprintf(tmp, "%02x",  *( (uint8_t *)data + i));
    Serial.write(tmp);  
  }
  Serial.write("\n");
}

void boho_index_print_hex( int num , char* titleStr, uint8_t* data, size_t len){
  char tmp[24] = {0};
  snprintf(tmp, sizeof(tmp), "#%d ", num);
  Serial.write( tmp );  
  boho_print_hex( titleStr, data, len );
}

void boho_convert_hex( char* output, const void* input, size_t inputLen){
  for(int i=0; i< inputLen; i++){
    sprintf( output + i * 2, "%02x",  *((uint8_t* )input + i ) );
  }
}
// Checked overloads distinguish successful empty payloads from rejection.
// The caller must provide output capacity for the declared plaintext length.
bool Boho::decryptPack(void *output, const uint8_t *input, uint32_t inputLen, uint32_t &length)
{
  length = 0;
  if (!hasKey || !input || inputLen < MetaSize_ENC_PACK || inputLen > (uint32_t)((size_t)-1) ||
      input[0] != ENC_PACK) return false;
  u32buf4 declared;
  memcpy(declared.buf, input + 1, 4);
  const uint32_t size = declared.u32;
  if (size != inputLen - MetaSize_ENC_PACK || (!output && size)) return false;
  uint8_t expected[8];
  memcpy(expected, input + 17, 8);
  set_salt12(input + 5);
  resetOTP();
  if (size) memmove(output, input + MetaSize_ENC_PACK, size);
  xotp((uint8_t *)output, size);
  if (!generateHMAC(output, size) || memcmp(_hmac, expected, 8)) {
    if (size) memset(output, 0, size);
    return false;
  }
  length = size;
  return true;
}

bool Boho::decrypt_488(void *output, const uint8_t *input, uint32_t inputLen, uint32_t &length)
{
  length = 0;
  if (!isAuthorized || !hasKey || !input || inputLen < MetaSize_ENC_488 || inputLen > (uint32_t)((size_t)-1) ||
      (input[0] != ENC_488 && input[0] != ENC_E2E)) return false;
  u32buf4 declared;
  memcpy(declared.buf, input + 1, 4);
  const uint32_t size = declared.u32;
  if (size > inputLen - MetaSize_ENC_488 || (!output && size) ||
      (input[0] == ENC_488 && size != inputLen - MetaSize_ENC_488)) return false;
  u16buf2 ms;
  memcpy(ms.buf, input + 9, 2);
  if (ms.u16 >= 1000) return false;
  uint8_t expected[8];
  memcpy(expected, input + 13, 8);
  memcpy(_otpSrc44 + 32, input + 5, 8);
  memcpy(_otpSrc44 + 40, localNonce.buf, 4);
  resetOTP();
  if (size) memmove(output, input + MetaSize_ENC_488, size);
  xotp((uint8_t *)output, size);
  if (!generateHMAC(output, size) || memcmp(_hmac, expected, 8)) {
    if (size) memset(output, 0, size);
    return false;
  }
  length = size;
  return true;
}

bool Boho::decrypt_e2e(void *output, const uint8_t *input, uint32_t inputLen,
                       const char *key, uint32_t &length)
{
  length = 0;
  if (!key || !*key) return false;
  uint8_t backup[32];
  memcpy(backup, _otpSrc44, 32);
  const bool previousKey = hasKey;
  set_key(key);
  const bool success = decryptPack(output, input, inputLen, length);
  memcpy(_otpSrc44, backup, 32);
  hasKey = previousKey;
  memset(backup, 0, sizeof(backup));
  return success;
}

int Boho::auth_req(uint8_t *output)
{
  if (!hasChallenge) return 0;
  return auth_req(output, serverChallenge, sizeof(serverChallenge));
}
