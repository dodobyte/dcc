#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "dcc.h"

#define outcode printf
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define IS_OPERATOR(type) ((type >= PLUS) && (type) <= UMINUS)
#define IS_VARTYPE(type) ((type) >= VOID && (type) <= CHAR)
#define IS_KEYWORD(type) ((type >= IF) && (type) <= RETURN)

#define PREC(oper) (op[(oper)->idx].prec)
#define ASSOC(oper) (op[(oper)->idx].assoc)

/* token types, order is important */
enum {	PLUS, MINUS, TIMES, DIV, MOD, CALL, LPARN, RPARN, 
	EQ, NEQ, LESS, LEQ, GREAT, GEQ, AND, OR, ASSIGN, COMMA, 
	SEMI, INC, DEC, ADDR, DEREF, UMINUS, LBRAC, RBRAC,
	/**/ CONST, STRING, IDENT, /**/ VOID, INT, CHAR, /**/ 
	IF, ELSE, FOR, WHILE, BREAK, CONTINUE, RETURN };

/* declaration scope */
enum { LOCAL, PARAM, GLOBAL };

/* identifier types */
enum { VARIABLE, FUNCTION };

/* operator association */
enum { RIGHT_ASSOC, LEFT_ASSOC };

const char *keywd[] = { 
	"void", "int", "char", "if", "else", "for",
	"while", "break", "continue", "return"
};

enum { EAX, EBX, ECX, EDX, ESI, EDI, NREG = 6 };
char *regs[] = { "eax", "ebx", "ecx", "edx", "esi", "edi" };

int nif;
int nfor;
int nwhile;
int line = 1;
int peek_tok;

int ncon;
int con[MAX_VAL];

int nidt;
char idt[MAX_NAME][NAME_LEN];

int nstr;
string str[MAX_NAME];

int nop;
operator op[MAX_OP];

int ncal;
call cal[MAX_NAME];

symlist sym;
symlist gsym;

loopch loop;

int ndec;
decass deca[MAX_PARAM];

void logo(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void error(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	fprintf(stderr, "%d: ", line);
	vfprintf(stderr, fmt, args);

	va_end(args);
	exit(1);
}

void dbgout(char *msg, output *outp)
{
	int i, idx = 0;
	char basic[5] = "+-*/%";

	logo("%s\t\t", msg);

	for (i = 0; i < outp->nout; i++) {
		idx = outp->tok[i].idx;

		switch (outp->tok[i].type) {
		case IDENT:
			logo("%s ", idt[idx]);
			break;
		case CONST:
			logo("%d ", con[idx]);
			break;
		case PLUS:
		case MINUS:
		case TIMES:
		case DIV:
		case MOD:
			logo("%c ", basic[outp->tok[i].type - PLUS]);
			break;
		case CALL:
			logo("%s() ", idt[cal[outp->tok[i].idx].idt]);
			break;
		case UMINUS:
			logo("_ ");
			break;
		case ASSIGN:
			logo("= ");
			break;
		case EQ:
			logo("== ");
			break;
		case NEQ:
			logo("!= ");
			break;
		case LEQ:
			logo("<= ");
			break;
		case GEQ:
			logo(">= ");
			break;
		case LESS:
			logo("< ");
			break;
		case GREAT:
			logo("> ");
			break;
		case AND:
			logo("&& ");
			break;
		case OR:
			logo("|| ");
			break;
		case STRING:
			logo("%s ", str[i].str);
			break;
		case INC:
			logo("++ ");
			break;
		case DEC:
			logo("-- ");
			break;
		case ADDR:
			logo("& ");
			break;
		}
	}
	logo("\n");
}

void *ecalloc(size_t num, size_t size)
{
	void *mem = calloc(num, size);
	if ( !mem ) {
		error("out of memory!\n");
	}
	return mem;
}

void *erealloc(void* mem, size_t size)
{
	void *newmem = realloc(mem, size);
	if ( !newmem ) {
		error("out of memory!\n");
	}
	return newmem;
}

void efree(void *mem)
{
	if ( mem ) {
		free(mem);
	}
}

int check_keyword(const char *str)
{
	int i;
	
	for (i = 0; i < ARRAY_SIZE(keywd); i++) {
		if (strcmp(str, keywd[i]) == 0) {
			return i + VOID;
		}
	}
	return -1;
}

int lookup_ident(char *name)
{
	int i, idx = 0;

	for (i = 0; i < nidt; i++) {
		if (strcmp(name, idt[i] + 1) == 0) {
			return i;
		}
	}

	idx = nidt++;
	idt[idx][0] = '_';
	strcpy(idt[idx] + 1, name);
	return idx;
}

char escape(int c)
{
	if (c == EOF || c == '\n') {
		error("nonterminated string\n");
	}

	if (c != '\\') {
		return (char)c;
	}

	c = getchar();

	switch (c) {
	case 't':
		return '\t';
	case 'n':
		return '\n';
	case '0':
		return '\0';
	case 'r':
		return '\r';
	case '\"':
		return '\"';
	case '\'':
		return '\'';
	}

	error("escape character\n");
	return '\0'; /* error */
}

token *get_token(void)
{
	static token tok;
	int c, cc, kw, sp = 0;
	char *arop = "+-*/%";
	char name[NAME_LEN] = {0};

	if (peek_tok) {
		peek_tok = 0;
		return &tok;
	}
read:
	c = getchar();

	/* white space, skip */
	while (isspace(c)) {
		if (c == '\n') {
			line++;
		}
		c = getchar();
	}

	/* ignore includes */
	if (c == '#') {
		while ((c = getchar()) != EOF) {
			if (c == '\n') {
				line++;
				goto read;
			}
		}
	}

	/* comment */
	if (c == '/') {
		if ((cc = getchar()) == '*') {
			while ((c = getchar()) != EOF) {
				if (c == '\n') {
					line++;
				}
				if (c != '*') {
					continue;
				}
				if ((c = getchar()) == '/') {
					goto read;
				}
				ungetc(c, stdin);
			}
			error("nonterminated comment\n");
		}
		ungetc(cc, stdin);
	}

	/* integer constant */
	if (isdigit(c)) {
		ungetc(c, stdin);
		tok.type = CONST;
		tok.idx = ncon;
		scanf("%d", &con[ncon++]);
		goto done;
	}

	/* character constant */
	if (c == '\'') {
		c = escape(getchar());
		if ((cc = getchar()) != '\'') {
			error("\' expected after constant\n");
		}
		tok.type = CONST;
		tok.idx = ncon;
		con[ncon++] = c;
		goto done;
	}

	/* string literal */
	if (c == '\"') {
		while (sp < STR_LEN && (cc = getchar()) != '\"') {
			str[nstr].str[sp++] = escape(cc);
		}
		if (cc != '\"') {
			error("\" expected after string\n");
		}
		sprintf(str[nstr].name, "str_%d", nstr);
		tok.type = STRING;
		tok.idx = nstr++;
		goto done;
	}

	/* identifier */
	if (c == '_' || isalpha(c)) {
		while (c == '_' || isalnum(c)) {
			if (sp < sizeof(name)) {
				name[sp++] = c;
			}
			c = getchar();
		}
		ungetc(c, stdin);

		if ((kw = check_keyword(name)) >= 0) {
			tok.type = kw;
		} else {
			tok.type = IDENT;
			tok.idx = lookup_ident(name);
		}
		goto done;
	}

	/* operator */
	switch (c) {
	case '+':
	case '-':
	case '*':
	case '/':
	case '%':
		tok.type = PLUS + (strchr(arop, c) - arop); /* enum order */
		if (tok.type <= MINUS) {
			switch (cc = getchar()) {
			case '+':
				tok.type = INC;
				break;
			case '-':
				tok.type = DEC;
				break;
			default:
				ungetc(cc, stdin);
			}
		}
		goto done;
	case ',':
		tok.type = COMMA;
		goto done;
	case ';':
		tok.type = SEMI;
		goto done;
	case '(':
	case ')':
		tok.type = (c == '(') ? LPARN : RPARN;
		goto done;
	case '{':
	case '}':
		tok.type = (c == '{') ? LBRAC : RBRAC;
		goto done;
	case '=':
		if ((cc = getchar()) == '=') {
			tok.type = EQ;
		} else {
			ungetc(cc, stdin);
			tok.type = ASSIGN;
		}
		goto done;
	case '!':
		if ((cc = getchar()) != '=') {
			error("= expected after !\n");
		}
		tok.type = NEQ;
		goto done;
	case '<':
	case '>':
		if ((cc = getchar()) == '=') {
			tok.type = (c == '<') ? LEQ : GEQ;
		} else {
			ungetc(cc, stdin);
			tok.type = (c == '<') ? LESS : GREAT;
		}
		goto done;
	case '&':
	case '|':
		if ((cc = getchar()) != c) {
			if (c == '&') {
				ungetc(cc, stdin);
				tok.type = ADDR;
				goto done;
			}
			error("%c expected after %c\n", c, c);
		}
		tok.type = (c == '&') ? AND : OR;
		goto done;
	}

	/* end of file */
	if (c == EOF) {
		tok.type = EOF;
		goto done;
	}
	error("unknown character: %d\n", c);

done:
	return &tok;
}

void push(opstack *opst, token *tokp)
{
	if (opst->sp < MAX_TOK) {
		opst->tok[opst->sp++] = *tokp;
	}
}

token *pop(opstack *opst)
{
	if (opst->sp == 0) {
		return NULL;
	}
	return &opst->tok[--opst->sp];
}

token *peek(opstack *opst)
{
	if (opst->sp == 0) {
		return NULL;
	}
	return &opst->tok[opst->sp - 1];
}

void putout(output *out, token *tokp)
{
	if (out->nout < MAX_TOK) {
		out->tok[out->nout++] = *tokp;
	}
}

void set_op(token *tok, int prec, int assoc)
{
	int i;
	i = tok->idx = nop++;
	op[i].prec = prec;
	op[i].assoc = assoc;
}

void arrange_stack(opstack *opst, output *out, token *tok)
{
	token *tmp = NULL;

	while ((tmp = peek(opst)) && tmp->type != LPARN) {
		if (PREC(tok) > PREC(tmp)) {
			break;
		}
		if (PREC(tok) == PREC(tmp) && ASSOC(tok) == RIGHT_ASSOC) {
			break;
		}
		tmp = pop(opst);
		putout(out, tmp);
	}
	push(opst, tok);
}

int handle_call(void)
{
	output *out = NULL;
	int idx, param = 0, nparam = 0;

	idx = ncal++;

	while (param == 0) {
		out = ecalloc(1, sizeof(*out));
		shunting_yard(out, 0, &param);
		if (out->nout) {
			//dbgout("handle_call", out);
			nparam = cal[idx].nparam++;
			cal[idx].param[nparam] = out;
		}
	}

	return idx;
}

void shunting_yard(output *out, int condexp, int *param)
{
	opstack *opst = NULL;
	token tok, prev = {-1, -1}, *tmp;
	opst = ecalloc(1, sizeof(*opst));

	for (;;) {
		tok = *get_token();

		switch (tok.type) {
		case LPARN:
			if (prev.type == IDENT) {
				out->nout--;
				tok.type = CALL;
				tok.idx = handle_call();
				cal[tok.idx].idt = prev.idx;
				putout(out, &tok);
				break;
			}
			push(opst, &tok);
			break;
		case RPARN:
			while ((tmp = peek(opst))) {
				tmp = pop(opst);
				if (tmp->type == LPARN) {
					break;
				}
				putout(out, tmp);
			}

			if (param && tmp == NULL) { /* call */
				efree(opst);
				*param = 1;
				return;
			}
			if (condexp && peek(opst) == NULL) { /* if, while () */
				efree(opst);
				return;
			}
			if (tmp == NULL) { /* for */
				efree(opst);
				return;
			}
			break;
		case COMMA:
			while ((tmp = peek(opst))) {
				tmp = pop(opst);
				if (tmp->type == LPARN) {
					break;
				}
				putout(out, tmp);
			}
			efree(opst);
			return;
		case PLUS:
		case MINUS:
			if (tok.type == MINUS && 
				(prev.type == -1 ||IS_OPERATOR(prev.type)) && 
							prev.type != RPARN) {
				tok.type = UMINUS;
				set_op(&tok, 8, RIGHT_ASSOC);
				push(opst, &tok);
				break;
			}
			set_op(&tok, 6, LEFT_ASSOC);
			arrange_stack(opst, out, &tok);
			break;
		case TIMES:
		case DIV:
		case MOD:
			if (tok.type == TIMES && 
				(prev.type == -1 ||IS_OPERATOR(prev.type)) && 
							prev.type != RPARN) {
				tok.type = DEREF;
				set_op(&tok, 8, RIGHT_ASSOC);
				push(opst, &tok);
				break;
			}
			set_op(&tok, 7, LEFT_ASSOC);
			arrange_stack(opst, out, &tok);
			break;
		case INC:
		case DEC:
			set_op(&tok, 8, RIGHT_ASSOC);
			push(opst, &tok);
			break;
		case ADDR:
			set_op(&tok, 8, RIGHT_ASSOC);
			push(opst, &tok);
			break;		
		case ASSIGN:
			set_op(&tok, 1, RIGHT_ASSOC);
			arrange_stack(opst, out, &tok);
			break;
		case EQ:
		case NEQ:
			set_op(&tok, 4, LEFT_ASSOC);
			arrange_stack(opst, out, &tok);
			break;
		case LEQ:
		case GEQ:
		case LESS:
		case GREAT:
			set_op(&tok, 5, LEFT_ASSOC);
			arrange_stack(opst, out, &tok);
			break;
		case AND:
			set_op(&tok, 3, LEFT_ASSOC);
			arrange_stack(opst, out, &tok);
			break;
		case OR:
			set_op(&tok, 2, LEFT_ASSOC);
			arrange_stack(opst, out, &tok);
			break;
		case IDENT:
		case CONST:
		case STRING:
			putout(out, &tok);
			break;
		case SEMI:
			while ((tmp = peek(opst))) {
				tmp = pop(opst);
				putout(out, tmp);
			}
			efree(opst);
			return;
		default:
			error("expression\n");
			return;
		}
		prev = tok;
		tok.type = 0;
	}
}

void alloc_reg(int *reg1, int *reg2, int op, symst *sst)
{
	if (sst->n > NREG) {
		outcode("\tpush	ebx\n");
		outcode("\tmov	ebx, [esp + %d]\n", 4);

		if (sst->s[--sst->n] == IDENT) {
			outcode("\tmov	ebx, [ebx]\n");
		}
		*reg2 = EBX;
	} else {
		*reg2 = --sst->n;
		if (sst->s[sst->n] == IDENT) {
			outcode("\tmov	%s, [%s]\n", 
				regs[*reg2], regs[*reg2]);
		}
	}

	if (sst->n > NREG) {
		outcode("\tpush	eax\n");
		outcode("\tmov	eax, [esp + %d]\n", 12);

		if (sst->s[--sst->n] == IDENT && op != ASSIGN) {
			outcode("\tmov	eax, [eax]\n");
		}
		*reg1 = EAX;
	} else {
		*reg1 = --sst->n;
		if (sst->s[sst->n] == IDENT && op != ASSIGN) {
			outcode("\tmov	%s, [%s]\n", 
				regs[*reg1], regs[*reg1]);
		}	
	}
}

void free_reg(symst *sst)
{
	if (sst->n < NREG - 1) {
		return;
	}

	if (sst->n > NREG - 1) {
		outcode("\tmov	[esp + 12], eax\n");
		outcode("\tpop	eax\n");
		outcode("\tpop	ebx\n");
		outcode("\tadd	esp, 4\n");
	} else {
		outcode("\tpop	ebx\n");
	}
}

void eval_divmod(int op, int reg1, int reg2)
{
	if (reg1 != EAX) {
		outcode("\tpush	eax\n");
		outcode("\tmov	eax, %s\n", regs[reg1]);
	}

	outcode("\tpush	edx\n");
	outcode("\txor	edx, edx\n");
	outcode("\tidiv	%s\n", regs[reg2]);

	if (op == MOD) {
		outcode("\tmov	eax, edx\n");
	}

	outcode("\tpop	edx\n");

	if (reg1 != EAX) {
		outcode("\tmov	%s, eax\n", regs[reg1]);
		outcode("\tpop	eax\n");
	}
}

void eval_binary(int op, symst *sst)
{
	int reg1 = 0, reg2 = 0, c1, c2;

	alloc_reg(&reg1, &reg2, op, sst);

	switch (op) {
	case PLUS:
	case MINUS:
		outcode("\t%s	%s, %s\n", (op == PLUS) ? "add" : "sub",
			regs[reg1], regs[reg2]);
		break;
	case TIMES:
		outcode("\timul	%s, %s\n", regs[reg1], regs[reg2]);
		break;
	case DIV:
	case MOD:
		eval_divmod(op, reg1, reg2);
		break;
	case ASSIGN:
		outcode("\tmov	[%s], %s\n", regs[reg1], regs[reg2]);
		outcode("\tmov	%s, [%s]\n", regs[reg1], regs[reg1]);
		break;
	case AND:
	case OR: /* TODO reg > edx ise patlicak direk */
		c1 = regs[reg1][1];
		c2 = regs[reg2][1];
		if (reg1 > EDX || reg2 > EDX) {
			error("TODO: eval_binary\n");
		}
		outcode("\tcmp	%s, 0\n", regs[reg1]);
		outcode("\tsetne	%cl\n", c1);
		outcode("\tcmp	%s, 0\n", regs[reg2]);
		outcode("\tsetne	%cl\n", c2);
		outcode("\t%s	%cl, %cl\n", 
			(op == AND) ? "and" : "or", c1, c2);
		outcode("\tmovzx	%s, %cl\n", regs[reg1], c1);
		break;
	case EQ:
	case NEQ:
	case LESS:
	case LEQ:
	case GREAT:
	case GEQ:
	{	/* TODO reg > edx ise patlicak */
		char *end[] = { "e", "ne", "l", "le", "g", "ge" };
		c1 = regs[reg1][1];
		if (reg1 > EDX || reg2 > EDX) {
			error("TODO: eval_binary\n");
		}
		outcode("\tcmp	%s, %s\n", regs[reg1], regs[reg2]);
		outcode("\tset%s	%cl\n", end[op - EQ], c1);
		outcode("\tmovzx	%s, %cl\n", regs[reg1], c1);
	}
		break;
	}

	free_reg(sst);
}

void eval_unary(int op, symst *sst)
{
	int idt, reg;

	if (sst->n > NREG) { /* TODO sunu hallet */
		error("TODO: eval_unary\n");
		outcode("\tpush	eax\n");
		outcode("\tmov	eax, [esp + %d]\n", 4);

		if (sst->s[--sst->n] == IDENT) {
			outcode("\tmov	eax, [eax]\n");
		}
		reg = EAX;
	} else {
		reg = --sst->n;
		idt = sst->s[sst->n] == IDENT;

		if (!idt && (op == INC || op == DEC || op == ADDR)) {
			error("lvalue required for ++,--, &\n");
		}

		switch (op) {
		case INC:
		case DEC:
			outcode("\tpush	dword[%s]\n", regs[reg]);

			switch (op) {
			case INC:
				outcode("\tinc	dword[%s]\n", regs[reg]);
				break;
			case DEC:
				outcode("\tdec	dword[%s]\n", regs[reg]);
				break;
			}
			outcode("\tpop	%s\n", regs[reg]);
			break;
		case ADDR:
			break;
		case DEREF:
			outcode("\tmov	%s, [%s]\n", regs[reg], regs[reg]);
			break;
		case UMINUS:
			if (idt) {
				outcode("\tmov	%s, [%s]\n", 
						regs[reg], regs[reg]);
				outcode("\tneg	%s\n", regs[reg]);
			} else {
				outcode("\tneg	%s\n", regs[reg]);
			}
			break;
		}
	}
}

void eval_call(int idx, int nsym)
{
	int i, last = 0;

	last = cal[idx].nparam - 1;

	outcode("\tpusha\n");

	for (i = last; i >= 0 ; i--) {
		//dbgout("eval_call", cal[idx].param[i]);
		eval_expr(cal[idx].param[i]);
		outcode("\tpush	eax\n");
	}

	outcode("\tcall	%s\n", idt[cal[idx].idt]);
	if (cal[idx].nparam) {
		outcode("\tadd	esp, %d\n", cal[idx].nparam * 4);
	}
	outcode("\tmov	[ebp -4000], eax\n");
	outcode("\tpopa\n");
	
	if (nsym < NREG) {
		outcode("\tmov	%s, [ebp -4000]\n", regs[nsym]);
	} else {
		outcode("\tpush	dword[ebp -4000]\n");
	}
}

void push_ident(int idx, symst *sst)
{
	int i, fi = -1;

	for (i = 0; i < sym.nidt; i++) {
		if (idx == sym.idt[i]) {
			fi = i;
			break;
		}
	}

	if (fi != -1) {
		if (sst->n < NREG) {
			outcode("\tlea	%s, [ebp + %d]\n", 
				regs[sst->n], sym.ebp[fi]);
		} else {
			outcode("\tpush	eax\n");
			outcode("\tlea	eax, [ebp + %d]\n", sym.ebp[fi]);
			outcode("\txchg	eax, [esp]\n");		
		}
		return;
	}

	for (i = 0; i < gsym.nidt; i++) {
		if (idx == gsym.idt[i]) {
			fi = i;
			break;
		}
	}

	if (fi != -1) {
		if (sst->n < NREG) {
			outcode("\tmov	%s, %s\n", regs[sst->n], idt[idx]);
		} else {
			error("TODO: push_ident, global\n");
			outcode("\tpush	%s\n", idt[idx]);
		}
		return;
	}

	error("%s undeclared\n", idt[idx] + 1);
}

void eval_expr(output *out)
{
	int i, type = 0, idx = 0;
	symst sst = {0};

	sst.s = calloc(MAX_TOK, sizeof(*sst.s));

	for (i = 0; i < out->nout; i++) {

		idx = out->tok[i].idx; 
		type = out->tok[i].type;

		switch(type) {
		case CONST:
			if (sst.n < NREG) {
				outcode("\tmov	%s, %d\n", 
					regs[sst.n], con[idx]);
			} else {
				outcode("\tpush	%d\n", con[idx]);
			}
			sst.s[sst.n++] = CONST;
			break;
		case IDENT:
			push_ident(idx, &sst);
			sst.s[sst.n++] = IDENT;
			break;
		case STRING:
			if (sst.n < NREG) {
				outcode("\tmov	%s, %s\n", 
					regs[sst.n], str[idx].name);
			} else {
				outcode("\tpush	%s\n", str[idx].name);
			}
			sst.s[sst.n++] = STRING;
			break;
		case INC:
		case DEC:
		case ADDR:
		case DEREF:
		case UMINUS:
			eval_unary(type, &sst);
			if (type == DEREF) {
				sst.s[sst.n++] = IDENT;
			} else {
				sst.s[sst.n++] = CONST;
			}
			break;
		case CALL:
			eval_call(idx, sst.n);
			sst.s[sst.n++] = CONST;
			break;
		default:
			eval_binary(type, &sst);
			sst.s[sst.n++] = CONST;
			break;
		}
	}

	if (sst.s[--sst.n] == IDENT) {
		outcode("\tmov	eax, [eax]\n");
	}

	efree(sst.s);
}

void expression(int condexp)
{
	output *out = NULL;

	out = ecalloc(1, sizeof(*out));

	shunting_yard(out, condexp, NULL);
	//dbgout("expression", out);
	eval_expr(out);

	efree(out);
}

void do_if(void)
{
	token *tok = NULL;
	int lnif = nif++;

	tok = get_token();
	if (tok->type != LPARN) {
		error("no ( after if\n");
	}
	peek_tok = 1;

	expression(1);

	outcode("\ttest	eax, eax\n");
	outcode("\tje	inope_%d\n", lnif);
	block();

	if (get_token()->type == ELSE) {
		outcode("\tjmp	idone_%d\n", lnif);
		outcode("inope_%d:\n", lnif);
		block();
		outcode("idone_%d:\n", lnif);

	} else {
		peek_tok = 1;
		outcode("inope_%d:\n", lnif);
	}
}

void do_while(void)
{
	token *tok = NULL;
	loopch *lp, *new;
	int lnwhile = nwhile++;

	for (lp = &loop; lp->next != NULL; lp = lp->next)
		;
	new = ecalloc(1, sizeof(*new));
	new->type = WHILE;
	new->label = lnwhile;
	lp->next = new;

	outcode("wloop_%d:\n", lnwhile);

	tok = get_token();
	if (tok->type != LPARN) {
		error("no ( after while\n");
	}
	peek_tok = 1;

	expression(1);

	outcode("\ttest	eax, eax\n");
	outcode("\tje	wdone_%d\n", lnwhile);
	block();
	outcode("\tjmp	wloop_%d\n", lnwhile);
	outcode("wdone_%d:\n", lnwhile);

	lp->next = NULL;
	efree(new);
}

void do_for(void)
{
	token *tok = NULL;
	loopch *lp, *new;
	int lnfor = nfor++;

	for (lp = &loop; lp->next != NULL; lp = lp->next)
		;
	new = ecalloc(1, sizeof(*new));
	new->type = FOR;
	new->label = lnfor;
	lp->next = new;

	tok = get_token();
	if (tok->type != LPARN) {
		error("no ( after for\n");
	}

	expression(0);

	outcode("cond_%d:\n", lnfor);
	expression(1);
	outcode("\tjmp	body_%d\n", lnfor);

	outcode("last_%d:\n", lnfor);
	expression(0);
	outcode("\tjmp	cond_%d\n", lnfor);

	outcode("body_%d:\n", lnfor);
	outcode("\ttest	eax, eax\n");
	outcode("\tje	fdone_%d\n", lnfor);
	block();
	outcode("\tjmp	last_%d\n", lnfor);
	outcode("fdone_%d:\n", lnfor);

	lp->next = NULL;
	efree(new);
}

void do_break(void)
{
	loopch *lp;

	if (loop.next == NULL) {
		error("break not in loop\n");
	}

	for (lp = &loop; lp->next != NULL; lp = lp->next)
		;
	if (lp->type == FOR) {
		outcode("\tjmp	fdone_%d\n", lp->label);
	} else {
		outcode("\tjmp	wdone_%d\n", lp->label);
	}
}

void do_continue(void)
{
	loopch *lp;

	if (loop.next == NULL) {
		error("continue not in loop\n");
	}

	for (lp = &loop; lp->next != NULL; lp = lp->next)
		;
	if (lp->type == FOR) {
		outcode("\tjmp	last_%d\n", lp->label);
	} else {
		outcode("\tjmp	wloop_%d\n", lp->label);
	}
}

void do_return(void)
{
	expression(0);
	outcode("\tleave\n");
	outcode("\tret\n");
}

int statement(void)
{
	token *tok =  get_token();

	switch (tok->type) {
	case IF:
		do_if();
		break;
	case WHILE:
		do_while();
		break;
	case FOR:
		do_for();
		break;
	case BREAK:
		do_break();
		break;
	case CONTINUE:
		do_continue();
		break;
	case RETURN:
		do_return();
		break;
	case LBRAC:
		peek_tok = 1;
		block();
		break;
	case RBRAC:
		return 0;
	default:
		peek_tok = 1;
		expression(0);
		break;
	}
	return 1;
}

void block(void)
{
	token *tok = NULL;
	int i, start = 0, nvar = 0;

	tok = get_token();
	if (tok->type != LBRAC) {
		error("{ expected\n");
	}

	nvar = declare(LOCAL);

	start = sym.nidt - nvar;

	for (i = start; i < sym.nidt; i++) {
		sym.ebp[i] = -sym.ebpx;
		sym.ebpx += 4;
	}

	for (i = 0; i < ndec; i++) {
		eval_expr((output *)&deca[i]);
	}
	ndec = 0;

	while (statement()) {
		;
	}
}

void new_stack(int param)
{
	int i, nparam = 0;

	if (param) {
		nparam = declare(PARAM);

		for (i = 0; i < nparam; i++) {
			sym.ebp[i] = i * 4 + 8;
		}
	}
	sym.ebpx = 4;
}

void function(int idx)
{
	int param = 0;
	token *tok = NULL;

	outcode("\n%s:\n", idt[idx]);
	outcode("\tpush	ebp\n");
	outcode("\tmov	ebp, esp\n");
	outcode("\tsub	esp, 4096\n");

	tok = get_token();

	if (tok->type == VOID) {
		tok = get_token();
		if (tok->type != RPARN) {
			error("void variable\n");
		}
	} else if (tok->type == RPARN) {
		/* no param */;
	} else {
		peek_tok = 1;
		param = 1;
	}

	new_stack(param);
	block();
	undeclare();
	outcode("\tleave\n");
	outcode("\tret\n");
}

void define_ident(symlist *sym, int idx, int type)
{
	int i, szidt = 0, sztype = 0;

	if (sym->nidt == sym->size) {
		sym->size += ALLOC_SIZE;

		szidt = sym->size * sizeof(*sym->idt);
		sztype = sym->size * sizeof(*sym->type);

		sym->idt = erealloc(sym->idt, szidt);
		sym->type = erealloc(sym->type, sztype);
	}

	for (i = 0; i < sym->nidt; i++) {
		if (idx == sym->idt[i]) {
			error("%s redeclared\n", idt[idx]);
		}
	}

	sym->idt[sym->nidt] = idx;
	sym->type[sym->nidt] = type;
	sym->nidt++;
}

int declare_one(int scope, int *idx, int *type)
{
	int vtype = 0;
	static int comma = 0;
	token *tok = get_token();

	if (tok->type == EOF) {
		return 0;
	}

	if (!IS_VARTYPE(tok->type)) {
		peek_tok = 1;
		if (!comma) {
			return 0;
		}
	}
	vtype = tok->type;

	tok = get_token();
	if (tok->type != IDENT) {
		if (tok->type == TIMES) {
			tok = get_token();
		} else {
			error("not identifier: %d\n", tok->type);
		}
	}

	*idx = tok->idx;
	*type = VARIABLE;

again:
	switch (get_token()->type) {
	case SEMI:
		if (scope == PARAM) {
			error("; in parameter list\n");
		}
		comma = 0;
		break;
	case LPARN:
		if (scope != GLOBAL) {
			error("nonglobal function\n");
		}
		*type = FUNCTION;
		break;
	case COMMA:
		comma = 1;
		break;
	case RPARN:
		if (scope != PARAM) {
			error(") in declaration\n");
		}
		comma = 0;
		break;
	case ASSIGN:
	{
		decass *d = NULL;
		tok = get_token();
		if (tok->type != CONST && tok->type != IDENT) {
			error("invalid assignment\n");
		}
		d = &deca[ndec];
		d->nout = 3;
		d->tok[0].type = IDENT;
		d->tok[0].idx = *idx;
		d->tok[1] = *tok;
		d->tok[2].type = ASSIGN;
		ndec++;
		goto again;
		break;
	}
	default:
		error("invalid declaration\n");
		break;
	}

	if (vtype == VOID && *type == VARIABLE) {
		error("void variable\n");
	}
	return 1;
}

void undeclare(void)
{
	efree(sym.idt);
	efree(sym.type);
	memset(&sym, 0, sizeof(sym));
}

int declare(int scope)
{
	symlist *symp = NULL;
	int idx = 0, type = 0, ndecl = 0;

	symp = (scope == GLOBAL) ? &gsym : &sym;

	while (declare_one(scope, &idx, &type)) {

		define_ident(symp, idx, type);

		if (scope == GLOBAL && type == FUNCTION) {
			function(idx);
		}
		ndecl++;
	}
	return ndecl;
}

void external(void)
{
	outcode("[bits 32]\n\n");
	outcode("global _start\n\n");
	outcode("section .text\n");

	declare(GLOBAL);

	outcode("\n_start:\n");
	outcode("\tcall _main\n");
	outcode("\tpush 0\n");
	outcode("\tcall _exit\n");
	outcode("\tret\n");
}

void data_out(void)
{
	int i, j, idx, len = 0, Main = 0;

	outcode("\n\nsection .data\n\n");

	for (i = 0; i < gsym.nidt; i++) {

		idx = gsym.idt[i];

		if (gsym.type[i] == VARIABLE) {
			outcode("%s\tdd\t0\n", idt[idx]);
		} else {
			if (strcmp(idt[idx], "_main") == 0) {
				Main = 1;
			}
		}
	}

	for (i = 0; i < nstr; i++) {
		len = strlen(str[i].str);

		outcode("%s\tdb\t", str[i].name);
		for (j = 0; j < len; j++) {
			outcode("0x%02X, ", str[i].str[j]);
		}
		outcode("0x0\n");
	}

	outcode("\n\n");

	for (i = 0; i < ncal; i++) {

		int fi = -1, idx = cal[i].idt;

		for (j = 0; j < gsym.nidt; j++) {
			if (idx == gsym.idt[j]) {
				fi = i;
				break;
			}
		}
		if (fi == -1) {
			outcode("extern	%s\n", idt[idx]);
		}
	}
	outcode("extern	_exit\n");

	if (!Main) {
		line = 0;
		error("no main defined\n");
	}
}

int dal_main(int argc, char *argv[]);

int main(int argc, char *argv[])
{
	char *dalprm[2] = {0};
	int nstr = 0;
	char outname[256];

	FILE *fin = stdin, *fout = stdout;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: dcc file.c [-asm]\n");
		return 1;
	}

	nstr = strlen(argv[1]);
	if (nstr > 2 && strcmp(argv[1] + nstr - 2, ".c") == 0) {
		sprintf(outname, "%.*s.asm", nstr - 2, argv[1]);
	} else {
		sprintf(outname, "%s.asm", argv[1]);
	}

	fin = freopen(argv[1], "r", stdin);
	if (fin == NULL) {
		error("cannot open file: %s\n", argv[1]);
	}

	fout = freopen(outname, "w", stdout);
	if (fout == NULL) {
		error("cannot open file: %s\n", argv[2]);
	}

	external();
	data_out();

	fclose(fin);
	fclose(fout);

	dalprm[0] = "";
	dalprm[1] = outname;
	dal_main(2, dalprm);

	if (argc < 3 || strcmp(argv[2], "-asm") != 0) {
		remove(outname);
	}
	return 0;
}
