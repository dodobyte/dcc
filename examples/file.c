#include <stdio.h>

int main()
{
	int *file = 0;
	
	file = fopen("test.txt", "w");
	fprintf(file, "Hello World!\n");
	fclose(file);
	
	return 0;
}
