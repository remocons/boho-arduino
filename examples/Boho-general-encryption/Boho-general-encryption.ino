#include <Boho.h>

Boho boho;

#define SIZE 50

char plainData[SIZE];
uint8_t encData[SIZE + MetaSize_ENC_PACK ]; // !! encoded data pack size will be incresed.
char decData[SIZE ];  

int txCounter = 0;

void setup()
{
  Serial.begin(115200);
  boho.set_key("SECURE_PASSPHRASE");
}

// generate secret pack with incresing number string.
// and decrypt secret pack.
void loop(){
  
  // clear dec buffer
  memset(decData,0 , SIZE);
  
  // set plain data with variable string data.
  sprintf( plainData , "=== counter %04u ===", txCounter++);

  // show plain data : string, hex
  Serial.print( "\nplain data: ");
  Serial.print( plainData);
  int len = strlen( plainData );
  boho_print_hex( "\nbefore:", plainData, len  );

  // encryptPack( out_buffer, in_buffer,  in_size ): encPack_size
  int packSize = boho.encryptPack( encData, plainData, len  );

  Serial.print("enc pack size: ");
  Serial.println(packSize);

  // show secretPack
  boho_print_hex( "secretPack:", encData, packSize );
      
  // decryptPack and print 
  int decLen = boho.decryptPack( decData, encData, packSize);
  if( decLen > 0 ){ // success
    Serial.print("decrypted size:");
    Serial.println( decLen);
    Serial.print("dec data: ");
    // Serial.write( decData , decLen ); 
    Serial.println(decData);
  }else{ // fail.
    Serial.print("decryption failed.");
  }
  
  delay(500);
}

