#include <stdio.h>

int main()
{
  long e,d,n,M,temp;
  e=10;
  d=235;
  n=113;
  M=3;
  temp=M;
  int i;
  for(i=1;i<e;i++)
  {
   temp=temp*M;
   temp=temp%n;
  }
  printf("%ld\n",temp);
}
