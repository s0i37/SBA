#include <stdio.h>

void parse(char *buf)
{
	if(buf[0] == 'a' && buf[1] == 'b')
		printf("a\n");
	else
		printf("b\n");
}

int main(void)
{
	int i = 8;
	char * ptr = "ABDC12346789";
	parse(ptr);
	return 0;
}
