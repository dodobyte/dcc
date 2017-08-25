#ifndef __DCC_H
#define __DCC_H

typedef struct token token;
typedef struct string string;
typedef struct operator operator;

enum {	ALLOC_SIZE = 1024, NAME_LEN = 255, STR_LEN = 1024, MAX_NAME = 1024,
	MAX_PARAM = 32, MAX_VAL = 2048, MAX_OP = 3072, MAX_TOK = 2048 };

/* string literal */
struct string {
	char name[NAME_LEN];
	char str[STR_LEN];
};

struct operator {
	int prec;
	int assoc;
};

struct token {
	int type;
	int idx; /* index to arrays below */
};

/* shunting yard stack and output */
typedef struct opstack opstack;
typedef struct output output;
typedef struct decass decass;

struct opstack {
	unsigned int sp;
	token tok[MAX_TOK];
};

struct output {
	unsigned int nout;
	token tok[MAX_TOK];
};

struct decass {
	unsigned int nout;
	token tok[3];
};

typedef struct symlist symlist;

struct symlist {
	int size;
	int nidt;
	int ebpx;
	int *idt;
	union {
		int *ebp;
		int *type;
	};
	symlist *prev;
	symlist *next;
};

typedef struct call call;

struct call {
	int idt;
	int nparam;
	output *param[MAX_PARAM];
};

/* token type stack for code generation */
typedef struct symst symst;

struct  symst {
	int n;
	int *s;
};

typedef struct loopch loopch;

struct loopch {
	int type;
	int label;
	loopch *next;
};

void block(void);
int declare(int scope);
void undeclare(void);
void eval_expr(output *out);
void shunting_yard(output *out, int condexp, int *param);

#endif
