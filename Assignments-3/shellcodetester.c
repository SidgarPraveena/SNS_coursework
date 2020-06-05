#include <stdio.h>
#include <string.h>
 
char *shellcode = "\x53\x83\xec\x08\xe8\xa3\xfe\xff\xff\x81\xc3\x83\x1b\x00\x00\x83\xc4\x08\x5b\xc3";

int main(void)
{
(*(void(*)()) shellcode)();
return 0;
}
