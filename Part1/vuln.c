# include <stdio.h>
# include <string.h>
void function (char* input) {
  char buffer [64];

  strcpy(buffer,input) ;

}
int main (int argc, char* argv[]) {
  if (argc>1) {
    function(argv[1]) ;
  }
  else {
    printf("Usage: %s <input >\n",argv [0]) ;
  }
  return (0);
} //AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
