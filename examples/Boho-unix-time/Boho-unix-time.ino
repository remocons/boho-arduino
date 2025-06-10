#include <Boho.h>

Boho boho;

void setup()
{
  Serial.begin(115200);
  boho.setTime(86390 ); // set unixtime value.
}


void loop(){
  boho.refreshTime(); 
  Serial.print( "UNIX TIME: ");
  Serial.print( boho.getUnixTime() );  // print uint32_t number.
  boho_print_time( boho.getUnixTime() ); // print HH:MM:SS format.
  delay(800);
}

