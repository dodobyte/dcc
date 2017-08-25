#include <stdio.h>

int a, b;

int long_time(int num)
{
	int i, j, res, rem;
	
	res = 1;
	
	for (i = 0; i < num; i++) {
		for (j = 0; j < num; j++) {
			res = res + i * j;
			res++;
			rem = res % 19;
		}
	}
	printf("res: %d, rem: %d\n", res, rem);
}

int empty(void)
{
	printf("empty\n");
	return 6;
}

int fact(int n1)
{
	int i, res;
	
	res = 1;
	
	for (i = 1; i <= n1; i++) {
		res = res * i;
	}
	return res;
}

void input(void)
{
	int a, b;
	
	printf("enter two numbers: \n");
	
	scanf("%d", &a);
	scanf("%d", &b);
	
	printf("product: %d\n", a * b);
}

int main(int argc, char argv)
{
	int i, j, res, kes, tes, mes, yes, fes, nes;
	
	nes = fes = yes = mes = tes = kes = res = 10;

	res = (res + 12 + 8 * 100);

	a = 150;
	b = 120;

	if (a == 150 && b == 120 && b < 121 || a != 150) {
		printf("true\n");
	} else {
		printf("false\n");
	}

	printf("a + -b: %d\tempty: %d\n", a + -b, empty());

	printf("%d\n", 2 + 5 * 2 + fact(5));
	
	empty();

	printf("%d, %d, %d, %d\n", nes, fes, kes, res);

	printf("%d\n", 18 % 4 + 6 / 2);
	
	for (i = 0; i < 5; i++) {
		for (j = 0; j < 5; j++) {
			printf("\t%d, %d\n", i, j);
		}		
	}

	while (nes--) {
		if (nes == 5) {
			printf("5\n");
			break;
		}
		printf("\tnes: %d\n", nes);
	}

	printf("fact 5: %d, fact 6: %d, %d\n\n", fact(5), fact(6), -a++);

	for (a = 0; a < 5; a++) {
		printf("a = %d\n", a);
		if (a == 0) {
			continue;
		}
		for (b = 0; b < 5; b++) {
			printf("b = %d\n", b);
			if (b == 3) {
				break;
			}
		}
	}
	
	printf("\n%d, %d\n", a, b);
	input();
	printf("%d, %d\n", a, b);

	long_time(1000);
	
	getchar();
	getchar();
	printf("one more\n");
	getchar();
	return 0;
}
