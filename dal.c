#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "pe.h"

#define NHEADERS	0x200
#define	ALIGN		0x200
#define SECALIGN	0x1000

#define ALIGNED(x) ((x) + (ALIGN - (x) % ALIGN))
#define SECALIGNED(x) ((x) + (SECALIGN - (x) % SECALIGN))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

enum { AL, CL, DL, BL };

enum { EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI };

static char *regs[] = { 
	"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" 
};

enum {	ADD, SUB, IMUL, IDIV, CALL, JE, JMP, CMP, INC, DEC, NEG, 
	PUSHA, POPA, LEAVE, RET, TEST, XCHG, AND, OR, XOR, LEA, 
	SETXX, MOVZX, PUSH, POP, MOV, SYM };

char *instr[] = { 
	"add", "sub", "imul", "idiv", "call", "je", "jmp", "cmp", 
	"inc", "dec", "neg", "pusha", "popa", "leave", "ret", "test", 
	"xchg", "and", "or", "xor", "lea", "set..", "movzx", 
	"push", "pop", "mov" 
};

enum { LABEL, FUNC, IDENT };
enum { MAX_REF = 4096, MAX_SYM = 1024 };

typedef struct reference {
	int type;
	int pc;
	char name[32];
} reference;

int nref;
reference ref[MAX_REF];

int nsym;
reference sym[MAX_SYM];

int next;
char extrn[MAX_SYM][32];

enum { MAX_TEXT = 1024 * 1024, MAX_DATA = 1024 * 100, MAX_IDATA = 10 * 1024 };

int pc;
unsigned char *text;

int ndata;
unsigned char *data;

int nidata;
unsigned char *idata;

int ep;
int jmps;
int nline;
char set_[3];
FILE *fout;

enum { IMAGE_BASE = 0x400000, TEXT_BASE = 0x1000, 
	DATA_BASE = 0x2000, IDATA_BASE = 0x3000 };

static void logo(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

static void error(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	fprintf(stderr, "%d: ", nline);
	vfprintf(stderr, fmt, args);

	va_end(args);
	exit(1);
}

static void outcode(const char *fmt, ...)
{
	unsigned char op;
	int i, n, num = 0;

	va_list vl;
	va_start(vl, fmt);

	n = strlen(fmt);

	for (i = 0; i < n; i++) {
		switch (fmt[i]) {
		case 'o':
		case '1':
			op = va_arg(vl, int);
			*(text + pc) = op;
			pc += 1;
			break;
		case '4':
			num = va_arg(vl, int);
			*(int *)(text + pc) = num;
			pc += 4;
			break;
		}
	}

	va_end(vl);	
}

void skip_line(void)
{
	int c;

	while ((c = getchar()) != EOF) {
		if (c == '\n') {
			break;
		}
	}
}

void skip(void)
{
	int c, cc;
read:
	c = getchar();

	/* white space, skip */
	while (isspace(c)) {
		if (c == '\n') {
			nline++;
		}
		c = getchar();
	}

	if (c == ';') {
		skip_line();
		goto read;
	}

	if (c == ',' || c == ']') {
		goto read;
	}

	if (c == '[') {
		if ((cc = getchar()) == 'b') {
			skip_line();
			goto read;
		}
		ungetc(cc, stdin);
	}

	ungetc(c, stdin);
}

void ident(int pc)
{
	ref[nref].type = IDENT;
	ref[nref].pc = pc;
	scanf("%s", ref[nref].name);
	nref++;
}

static void function(int pc)
{
	ref[nref].type = FUNC;
	ref[nref].pc = pc;
	scanf("%s", ref[nref].name);
	nref++;
}

void label(int pc)
{
	ref[nref].type = LABEL;
	ref[nref].pc = pc;
	scanf("%s", ref[nref].name);
	nref++;
}

int find_ref(int type, char *name)
{
	int i;

	for (i = 0; i < nsym; i++) {
		if (sym[i].type == type) {
			if (!strcmp(sym[i].name, name)) {
				return sym[i].pc;
			}
		}
	}
	error("no such name: %s\n", name);
	return -1;
}

void fix_extern(void)
{
	int i, idata = 0;
	unsigned char func[] = { 0xFF, 0x25 };

	jmps = pc;

	for (i = 0; i < next; i++) {
		//logo("func: %s\n", extrn[i]);
		sym[nsym].type = FUNC;
		sym[nsym].pc = pc;
		strcpy(sym[nsym].name, extrn[i]);
		nsym++;

		memcpy(text + pc, func, sizeof(func));
		pc += sizeof(func);

		idata = IMAGE_BASE + IDATA_BASE;
		*(int *)(text + pc) = idata;
		pc += sizeof(idata);
	}
}

void fix_refs(void)
{
	int i, rpc, tpc, datasec;

	fix_extern();

	for (i = 0; i < nref; i++) {

		rpc = ref[i].pc;
		tpc = find_ref(ref[i].type, ref[i].name);
		
		switch (ref[i].type) {
		case LABEL:
			if (text[rpc] == 0xE9) {
				*(int *)(text + rpc + 1) = tpc - (rpc + 5);
			} else if (text[rpc] == 0x0F) {
				*(int *)(text + rpc + 2) = tpc - (rpc + 6);
			} else {
				error("invalid jmp/je\n");
			}
			break;
		case FUNC:
			*(int *)(text + rpc + 1) = tpc - (rpc + 5);
			break;
		case IDENT:
			datasec = IMAGE_BASE + DATA_BASE;
			*(int *)(text + rpc + 1) = datasec + tpc;
			break;
		}
	}
}

void fix_imports(void)
{
	int i;
	IMAGE_THUNK_DATA *org, *first;

	IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)idata;

	imp->u.OriginalFirstThunk = IDATA_BASE + sizeof(*imp) * 3;
	imp->FirstThunk = imp->u.OriginalFirstThunk + 
				(next + 1) * sizeof(IMAGE_THUNK_DATA);
	nidata = imp->FirstThunk + (next + 1) * sizeof(IMAGE_THUNK_DATA);

	imp->Name = nidata;
	strcpy((char *)idata + nidata - IDATA_BASE, "msvcrt.dll");
	nidata += (strlen("msvcrt.dll") + 2);

	org = (IMAGE_THUNK_DATA *)(idata + 
		(imp->u.OriginalFirstThunk - IDATA_BASE));
	first = (IMAGE_THUNK_DATA *)(idata + 
		(imp->FirstThunk - IDATA_BASE));

	for (i = 0; i < next; i++) {

		org[i].u1.AddressOfData = nidata;
		first[i].u1.AddressOfData = nidata;

		*(int *)(text + jmps + 6 * i + 2) = 
			IMAGE_BASE + imp->FirstThunk + 
			i * sizeof(IMAGE_THUNK_DATA);

		nidata += 2; /* hint */
		strcpy((char *)idata + nidata - IDATA_BASE, extrn[i] + 1);
		nidata += (strlen(extrn[i]) + 3);
	}

	nidata -= IDATA_BASE;
}

int set_symbol(char *str)
{
	int i;
	char *pcol;

	if (!strcmp(str, "global") || !strcmp(str, "section")) {
		skip_line();
		return 1;
	}

	if (!strcmp(str, "extern")) {
		scanf("%s", str);
		//logo("extern: %s\n", str);
		for (i = 0; i < next; i++) {
			if (!strcmp(extrn[i], str)) {
				return 1;
			}
		}
		strcpy(extrn[next++], str);
		return 1;
	}

	if (str[0] == '_') {
		if ((pcol = strchr(str, ':'))) {
			*pcol = '\0';
			//logo("func: %s\n", str);
			sym[nsym].type = FUNC;
			sym[nsym].pc = pc;
			strcpy(sym[nsym].name, str);
			nsym++;

			if (!strcmp(str, "_start")) {
				ep = TEXT_BASE + pc;
			}
		} else {
			//logo("ident: %s\n", str);
			sym[nsym].type = IDENT;
			sym[nsym].pc = ndata;
			strcpy(sym[nsym].name, str);
			nsym++;
			ndata += 4;
			skip_line();
		}
		return 1;
	}

	if (!strncmp(str, "str_", 4)) {
		unsigned int byte;
		//logo("ident: %s\n", str);
		sym[nsym].type = IDENT;
		sym[nsym].pc = ndata;
		strcpy(sym[nsym].name, str);
		nsym++;

		scanf("%s", str);
		if (strcmp(str, "db") != 0) {
			error("invalid string\n");
		}
		do {
			scanf("%X", &byte);
			if (byte) {
				getchar();
			}
			data[ndata++] = (unsigned char)byte;
		} while (byte != 0);
		return 1;	
	}

	if ((pcol = strchr(str, ':'))) {
		*pcol = '\0';
		//logo("label: %s\n", str);
		sym[nsym].type = LABEL;
		sym[nsym].pc = pc;
		strcpy(sym[nsym].name, str);
		nsym++;
		return 1;
	}

	return 0;
}

int get_instr(void)
{
	int i;
	char ins[256] = {0};

	skip();

	if (scanf("%s", ins) != 1) {
		return -1;
	}

	if (set_symbol(ins)) {
		return SYM;
	}

	if (strncmp(ins, "set", 3) == 0) {
		strncpy(set_, ins + 3, 2);
		return SETXX;
	}

	for (i = 0; i < ARRAY_SIZE(instr); i++) {
		if (strcmp(instr[i], ins) == 0) {
			return i;
		}
	}

	return -1;
}

int get_register(void)
{
	int i, c;
	char reg[256] = {0};

	skip();

	ungetc(c = getchar(), stdin);
	if (c != 'e') {
		return -1;
	}

	if (scanf("%3s", reg) != 1) {
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		if (strcmp(regs[i], reg) == 0) {
			return i;
		}
	}
	return -1;	
}

int get_reg8(void)
{
	int c;

	skip();

	c = getchar();
	getchar();

	switch (c) {
	case 'a':
		return 0;
	case 'b':
		return 3;
	case 'c':
		return 1;
	case 'd':
		return 2;
	default:
		error("invalid operand\n");
		return -1;
	}
}

int get_imm(void)
{
	int imm = 0;

	skip();

	if (scanf("%d", &imm) != 1) {
		error("invalid immediate\n");
	}

	return imm;	
}

void assemble_line(void)
{
	int c, ins, reg1, reg2, imm, sign = 1;
	char dword[10] = {0};

	nline++;

	switch ((ins = get_instr())) {
	case PUSHA:
		outcode("o", 0x60);
		break;
	case POPA:
		outcode("o", 0x61);
		break;
	case LEAVE:
		outcode("o", 0xC9);
		break;
	case RET:
		outcode("o", 0xC3);
		break;
	case TEST:
		outcode("oo", 0x85, 0xC0);
		skip_line();
		break;
	case XCHG:
		outcode("ooo", 0x87, 0x04, 0x24);
		skip_line();
		break;
	case XOR:
		outcode("oo", 0x31, 0xD2);
		skip_line();
		break;
	case AND:
		reg1 = get_reg8();
		reg2 = get_reg8();
		outcode("oo", 0x20, 0xC0 + reg2 * 8 + reg1);
		break;
	case OR:
		reg1 = get_reg8();
		reg2 = get_reg8();
		outcode("oo", 0x08, 0xC0 + reg2 * 8 + reg1);
		break;
	case POP:
		outcode("o", 0x58 + get_register());
		skip_line();
		break;
	case IDIV:
		outcode("oo", 0xF7, 0xF8 + get_register());
		skip_line();
		break;
	case NEG:
		outcode("oo", 0xF7, 0xD8 + get_register());
		skip_line();
		break;
	case MOVZX:
		outcode("ooo", 0x0F, 0xB6, 0xC0 + get_register() * 9);
		skip_line();
		break;
	case MOV:
		skip();
		c = getchar();

		if (c == '[') {
			reg1 = get_register();
			if (reg1 == -1) {
				error("mov, invalid register1\n");
			}
			if (reg1 == EBP) {
				while ((c = getchar()) != EOF) {
					if (c == '-') {
						break;
					}
				}
				imm = get_imm();
				skip();
				reg2 = get_register();
				if (reg2 == -1) {
					error("mov, invalid register2\n");
				}
				outcode("oo4", 
					0x89, 0x80 + reg2 * 8 + reg1, -imm);
				skip_line();
				break;
			}
			if (reg1 == ESP) {
				while ((c = getchar()) != EOF) {
					if (c == '+') {
						break;
					}
				}
				imm = get_imm();
				skip();
				reg2 = get_register();
				if (reg2 == -1) {
					error("mov, invalid register2\n");
				}
				outcode("oooo", 0x89, 0x40 + reg2 * 8 + reg1, 
						0x24, imm);
				skip_line();
				break;
			}
			skip();
			reg2 = get_register();
			if (reg2 == -1) {
				error("mov, invalid register\n");
			}
			outcode("oo", 0x89, reg2 * 8 + reg1);
			break;
		}
		ungetc(c, stdin);

		reg1 = get_register();
		if (reg1 == -1) {
			error("mov, invalid register\n");
		}

		skip();
		c = getchar();

		if (c == '[') {
			reg2 = get_register();
			if (reg2 == -1) {
				error("mov, invalid register\n");
			}
			if (reg2 == EBP) {
				while ((c = getchar()) != EOF) {
					if (c == '-') {
						break;
					}
				}
				imm = get_imm();
				outcode("oo4", 
					0x8B, 0x80 + reg1 * 8 + reg2, -imm);
				skip_line();
				break;
			}
			if (reg2 == ESP) {
				while ((c = getchar()) != EOF) {
					if (c == '+') {
						break;
					}
				}
				outcode("oooo", 0x8B, 0x40 + reg1 * 8 + reg2, 
						0x24, get_imm());
				skip_line();
				break;
			}
			outcode("oo", 0x8B, reg1 * 8 + reg2);
			skip_line();
			break;
		}

		if (c == '_' || c == 's') {
			ungetc(c, stdin);
			ident(pc);
			/* mov reg, ident */
			outcode("o4", 0xB8 + reg1, 0x11223344);
			skip_line();
			break;
		}
		ungetc(c, stdin);

		reg2 = get_register();
		if (reg2 == -1) {
			/* mov reg, n */
			outcode("o4", 0xB8 + reg1, get_imm());
			break;
		}
		/* mov reg, reg */
		outcode("oo", 0x89, 0xC0 + reg2 * 8 + reg1);
		break;
	case PUSH:
		reg1 = get_register();
		if (reg1 != -1) {
			outcode("o", 0x50 + reg1);
			break;
		}

		c = getchar();
		if (isdigit(c)) {
			ungetc(c, stdin);
			imm = get_imm();
			if (imm > 127 || imm < -128) {
				outcode("o1", 0x6A, imm);
			} else {
				outcode("o4", 0x68, imm);
			}
			break;
		}

		if (c != 'd') {
			error("invalid operand\n");
		}
		
		scanf("%5s", dword);
		reg1 = get_register();
		if (reg1 == -1 || reg1 == ESP) {
			error("invalid operand\n");
		}

		if (reg1 == EBP) {
			while ((c = getchar()) != EOF) {
				if (c == '+' || c == '-') {
					break;
				}
			}
			if (c == '-') {
				sign = -1;
			}
			outcode("oo4", 0xFF, 0xB5, get_imm() * sign);
			break;
		}
		outcode("oo", 0xFF, 0x30 + reg1);
		skip_line();
		break;
	case SETXX:
		reg1 = 0xC0 + get_reg8();

		switch (set_[0]) {
		case 'e':
			outcode("ooo", 0x0F, 0x94, reg1);
			break;
		case 'n':
			outcode("ooo", 0x0F, 0x95, reg1);
			break;
		case 'l':
			if (set_[1] == 'e') {
				outcode("ooo", 0x0F, 0x9E, reg1);
			} else {
				outcode("ooo", 0x0F, 0x9C, reg1);
			}
			break;
		case 'g':
			if (set_[1] == 'e') {
				outcode("ooo", 0x0F, 0x9D, reg1);
			} else {
				outcode("ooo", 0x0F, 0x9F, reg1);
			}
			break;
		default:
			error("unknown setxx\n");
			break;		
		}
		break;
	case INC:
	case DEC:
		while (getchar() != '[') {
			if (feof(stdin)) {
				break;
			}
		}
		reg1 = get_register();
		if (reg1 == -1) {
			error("invalid register\n");
		}
		outcode("oo", 0xFF, (ins == INC)? reg1 : reg1 + 8);
		skip_line();
		break;
	case LEA:
		reg1 = get_register();
		while (getchar() != '[') {
			if (feof(stdin)) {
				break;
			}
		}
		reg2 = get_register();
		while (getchar() != '+') {
			if (feof(stdin)) {
				break;
			}
		}
		if (reg1 == -1 || reg2 == -1) {
			error("invalid register\n");
		}
		outcode("oo1", 0x8D, 0x40 + reg2 + reg1 * 8, get_imm());
		skip_line();
		break;
	case CALL:
		function(pc);
		outcode("o4", 0xE8, 0x11223344);
		break;
	case JE:
		label(pc);
		outcode("oo4", 0x0F, 0x84, 0x11223344);
		break;
	case JMP:
		label(pc);
		outcode("o4", 0xE9, 0x11223344);
		break;
	case CMP:
		reg1 = get_register();
		reg2 = get_register();

		if (reg2 == -1) {
			if ((imm = get_imm()) > 127) {
				error("too big immediate\n");
			}
			outcode("oo1", 0x83, 0xF8 + reg1, imm);
		} else {
			outcode("oo", 0x39, 0xC0 + reg2 * 8 + reg1);
		}
		break;
	case IMUL:
		reg1 = get_register();
		reg2 = get_register();

		if (reg1 == -1 || reg2 == -1) {
			error("invalid instruction\n");
		}
		outcode("ooo", 0x0F, 0xAF, 0xC0 + reg1 * 8 + reg2);
		break;
	case ADD:
		reg1 = get_register();
		reg2 = get_register();

		if (reg2 == -1) {
			if (reg1 != ESP) {
				error("not supported\n");
			}
			if ((imm = get_imm()) > 127) {
				error("too big immediate\n");
			}
			outcode("oo1", 0x83, 0xC4, imm);
			break;
		}
		outcode("oo", 0x01, 0xC0 + reg2 * 8 + reg1);
		break;
	case SUB:
		reg1 = get_register();
		reg2 = get_register();

		if (reg2 == -1) {
			if (reg1 != ESP) {
				error("not supported\n");
			}
			outcode("oo4", 0x81, 0xEC, get_imm());
			break;
		}
		outcode("oo", 0x29, 0xC0 + reg2 * 8 + reg1);
		break;
	case SYM:
		break;
	default:
		if (feof(stdin)) {
			break;
		}
		error("unknown instruction\n");
		break;
	}
}

void assemble(void)
{
	while (!feof(stdin)) {
		assemble_line();
	}
}

int fill_null(int n)
{
	int i;
	char nul = 0;

	for (i = 0; i < n; i++) {
		fwrite(&nul, 1, 1, fout);
	}
	return i;
}

int write_dos(void)
{
	int n = 0;
	
	IMAGE_DOS_HEADER dos = {0};
	char *msg = "Compiled by DCC";

	dos.e_magic = IMAGE_DOS_SIGNATURE;
	dos.e_lfanew = 0x80;
	
	n += fwrite(&dos, 1, sizeof(dos), fout);
	n += fwrite(msg, 1, strlen(msg), fout);

	fill_null(0x80 - n);

	return 0x80;
}

int write_filehdr(void)
{
	int n = 0;
	IMAGE_FILE_HEADER file = {0};
	int pesig = IMAGE_NT_SIGNATURE;

	file.Machine = 0x014C;
	file.NumberOfSections = 3;
	file.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	file.Characteristics = 0x030F;

	n += fwrite(&pesig, 1, sizeof(pesig), fout);
	n += fwrite(&file, 1, sizeof(file), fout);
	return n;
}

int write_opthdr(void)
{
	IMAGE_OPTIONAL_HEADER opt = {0};

	int imgsize = SECALIGNED(NHEADERS) + SECALIGNED(pc) + 
			SECALIGNED(ndata) +  SECALIGNED(nidata);

	opt.Magic = 0x010B;
	opt.SizeOfCode = ALIGNED(pc);
	opt.SizeOfInitializedData = ALIGNED(ndata) + ALIGNED(nidata);
	opt.AddressOfEntryPoint = ep;
	opt.BaseOfCode = TEXT_BASE;
	opt.BaseOfData = DATA_BASE;
	opt.ImageBase = IMAGE_BASE;
	opt.SectionAlignment = SECALIGN;
	opt.FileAlignment = ALIGN;
	opt.MajorOperatingSystemVersion = 0x04;
	opt.MajorImageVersion = 0x01;
	opt.MajorSubsystemVersion = 0x04;
	opt.SizeOfImage = imgsize;
	opt.SizeOfHeaders = NHEADERS;
	opt.Subsystem = 0x03;
	opt.SizeOfStackReserve = 0x00200000;
	opt.SizeOfStackCommit = 0x00001000;
	opt.SizeOfHeapReserve = 0x00100000;
	opt.SizeOfHeapCommit = 0x00001000;
	opt.NumberOfRvaAndSizes = 0x0000010;
	opt.DataDirectory[1].VirtualAddress = IDATA_BASE;
	opt.DataDirectory[1].Size = nidata;

	return fwrite(&opt, 1, sizeof(opt), fout);
}

int write_section(void)
{
	int n = 0;
	IMAGE_SECTION_HEADER sec;

	memset(&sec, 0, sizeof(sec));
	memcpy(sec.Name, ".text", 6);
	sec.Misc.VirtualSize = pc;
	sec.VirtualAddress = TEXT_BASE;
	sec.SizeOfRawData = ALIGNED(pc);
	sec.PointerToRawData = NHEADERS;
	sec.Characteristics = 0x60500020;
	n += fwrite(&sec, 1, sizeof(sec), fout);

	memset(&sec, 0, sizeof(sec));
	memcpy(sec.Name, ".data", 6);
	sec.Misc.VirtualSize = ndata;
	sec.VirtualAddress = DATA_BASE;
	sec.SizeOfRawData = ALIGNED(ndata);
	sec.PointerToRawData = NHEADERS + ALIGNED(pc);
	sec.Characteristics = 0xC0300040;
	n += fwrite(&sec, 1, sizeof(sec), fout);

	memset(&sec, 0, sizeof(sec));
	memcpy(sec.Name, ".idata", 7);
	sec.Misc.VirtualSize = nidata;
	sec.VirtualAddress = IDATA_BASE;
	sec.SizeOfRawData = ALIGNED(nidata);
	sec.PointerToRawData = NHEADERS + ALIGNED(pc) + ALIGNED(ndata);
	sec.Characteristics = 0xC0300040;
	n += fwrite(&sec, 1, sizeof(sec), fout);

	return n;
}

void link(void)
{
	int n = 0;

	fix_refs();
	fix_imports();

	n += write_dos();
	n += write_filehdr();
	n += write_opthdr();
	n += write_section();

	n += fill_null(NHEADERS - n);
	n += fwrite(text, 1, pc, fout);

	n += fill_null(NHEADERS + ALIGNED(pc) - n);
	n += fwrite(data, 1, ndata, fout);

	n += fill_null(NHEADERS + ALIGNED(pc) + ALIGNED(ndata) - n);
	n += fwrite(idata, 1, nidata, fout);

	fill_null(0x200 - n % 0x200);

//	logo("pc: %X\tep: %X\tndata: %X\n", pc, ep, ndata);
}

int dal_main(int argc, char *argv[])
{
	int nstr = 0;
	char outname[256];
	FILE *fin = stdin;

	if (argc != 2) {
		logo("Usage: dal file.asm\n");
		return 1;
	}

	fin = freopen(argv[1], "r", stdin);
	if (fin == NULL) {
		error("cannot open file: %s\n", argv[1]);
	}
	
	nstr = strlen(argv[1]);

	if (nstr > 4 && strcmp(argv[1] + nstr - 4, ".asm") == 0) {
		sprintf(outname, "%.*s.exe", nstr - 4, argv[1]);
	} else {
		sprintf(outname, "%s.exe", argv[1]);
	}

	fout = fopen(outname, "wb");
	if (fout == NULL) {
		error("cannot open file: %s\n", outname);
	}

	text = calloc(1, MAX_TEXT);
	data = calloc(1, MAX_DATA);
	idata = calloc(1, MAX_IDATA);

	if (text == NULL || data == NULL || idata == NULL) {
		error("Out of memory\n");
	}

	assemble();
	link();

	fclose(fin);
	fclose(fout);
	free(text);
	free(data);
	return 0;
}
