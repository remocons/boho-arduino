#include <Boho.h>

Boho boho;

void setup()
{
  Serial.begin(115200);
  boho.setTime(86390 ); // set unixtime value.
}


void loop(){
  boho.refreshTime(); 
  Serial.print( "UNIX_TIME: ");
  Serial.print( boho.getUnixTime() );  // print uint32_t number.
  boho_print_time( boho.getUnixTime(), boho.getMilTime() ); // print HH:MM:SS:mm format.
  delay(90);
}

