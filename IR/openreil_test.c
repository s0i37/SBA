#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libopenreil.h>

#define MAX_ARG_STR 100

const char *inst_op[] =
{
    "NONE", "UNK", "JCC",
    "STR", "STM", "LDM",
    "ADD", "SUB", "NEG", "MUL", "DIV", "MOD", "SMUL", "SDIV", "SMOD",
    "SHL", "SHR", "AND", "OR", "XOR", "NOT",
    "EQ", "LT"
};
int arg_size[] = { 1, 8, 16, 32, 64 };

char * arg_print(reil_arg_t *arg, char *buf)
{
	memset(buf, 0, MAX_ARG_STR);
	switch(arg->type)
	{
		case A_NONE:
			snprintf(buf, MAX_ARG_STR-1, "");
			break;
		case A_REG:
		case A_TEMP:
			snprintf(buf, MAX_ARG_STR-1, "%s:%d", arg->name, arg_size[arg->size]);
			break;
		case A_CONST:
			snprintf(buf, MAX_ARG_STR-1, "%llx:%d", arg->val, arg_size[arg->size]);
			break;
	}
	return buf;
}

int inst_handler(reil_inst_t *inst, void *context)
{
	char buf[MAX_ARG_STR];
	*(int *)context++;

	printf( "0x%08x.%02x: %s ", inst->raw_info.addr, inst->inum, inst_op[inst->op] );
	printf( "%s, ", arg_print(&inst->a, buf) );
	printf( "%s, ", arg_print(&inst->b, buf) );
	printf( "%s\n", arg_print(&inst->c, buf) );
}

int main(void)
{
	unsigned char opcode[] = "\x83\xc0\x07"; // add eax, 7
	uint32_t len = 3;
	uint32_t translated = 0;
	reil_t reil = reil_init(ARCH_X86, inst_handler, &translated);
	reil_translate(reil, 0, opcode, len);
	reil_close(reil);
	return 0;
}

/* g++ openreil_test.c -I /usr/lib/openreil/include /usr/lib/openreil/lib/libopenreil.a */