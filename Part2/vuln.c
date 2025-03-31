# include <stdio.h>
# include <string.h>
void function (char* input) {
  char buffer [64];
  printf("Indirizzo di buffer: %p\n", &buffer);
  
  strcpy(buffer,input) ;

}
int main (int argc, char* argv[]) {
  if (argc>1) {
    function(argv[1]) ;
    printf("Ciao sono arrivato fino a qui :)\n");
  }
  else {
    printf("Usage: %s <input >\n",argv [0]) ;
  }
  return (0);
} //AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
