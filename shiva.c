#include "shiva.h"

bool
load_trace_data(struct shiva_ctx *ctx)
{
	elf_error_t error;
	struct elf_section section;
	uint64_t mode;
	uint8_t *code;

#if 0
	if (elf_open_object(ctx->path, &ctx->elfobj, ELF_LOAD_F_FORENSICS,
	    &error) == false) {
	    fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n", ctx->path,
		elf_error_msg(&error));
		return false;
	}
	if (elf_section_by_name(&ctx->elfobj, ".text", &section) == false) {
		fprintf(stderr, "elf_section_by_name failed to find \".text\"\n");
		return false;
	}
	mode = elf_class(&ctx->elfobj) == elfclass64 ? CS_MODE_64 : CS_MODE_32;
	ctx->disas.textptr = elf_address_pointer(&ctx->elfobj, section.address);
	if (ctx->disas.textptr == NULL) {
		fprintf(stderr, "elf_address_pointer(%p, %#lx) failed\n",
		    &ctx->elfobj, section.address);
		return false;
	}
	if (cs_open(CS_ARCH_X86, mode, &ctx->disas.handle) != CS_ERR_OK) {
		fprintf(stderr, "cs_open failed\n");
		return false;
	}
	int i;
	for (i = 0; i < section.size; i++) {
		printf("%02x ", ctx->disas.textptr[i]);
	}
	ctx->disas.count = cs_disasm(ctx->disas.handle, ctx->disas.textptr, section.size,
	    section.address, 0, &ctx->disas.insn);
	if (ctx->disas.count < 1) {
		fprintf(stderr, "cs_disasm_ex failed\n");
		return false;
	}
	for (i = 0; i < ctx->disas.count; i++) {
		printf("op_str: %s\n", ctx->disas.insn[i].op_str);
	}
#endif
	return true;
}

bool
build_target_argv(struct shiva_ctx *ctx, char **argv, int argc)
{
	char **p;
	int addend, i;

	/*
	 * If there are no initial shiva args, then build the
	 * argument vector starting from argv[1], otherwise from
	 * argv[2].
	 */
	addend = (argv[1][0] != '-') ? 1 : 2;

	ctx->path = shiva_strdup(argv[addend]);
	ctx->args = (char **)shiva_malloc((argc - addend) * sizeof(char *));
	for (i = 0, p = &argv[addend]; i != argc - addend; p++, i++)
		*(ctx->args + i) = shiva_strdup(*p);
	*(ctx->args + i) = NULL;
	ctx->argcount = i;
	return true;
}

int main(int argc, char **argv)
{
	shiva_ctx_t ctx;
	int opt, i, subend;

	struct sigaction act;
	sigset_t set;
	act.sa_handler = shiva_sighandle;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
	sigemptyset(&set);
	sigaddset(&set, SIGINT);

	if ((argc < 2) || (argc == 2 && argv[1][0] == '-')) {
		printf("Usage: %s [-sbr] <prog> [<prog> args]\n", argv[0]);
		printf("[-s] string values\n");
		printf("[-b] branch control flow\n");
		printf("[-r] return values\n");
		printf("Example: shiva -sbr /bin/ls -lR\n");
		exit(EXIT_FAILURE);
	}

	if (build_target_argv(&ctx, argv, argc) == false) {
		fprintf(stderr, "build_target_argv failed\n");
		return false;
	}

	if (argv[1][0] == '-') {
		char *p;

		for (p = &(*(*(argv + 1) + 1)); *p != '\0'; p++) {
			switch (*p) {
			case 's':
				ctx.flags |= SHIVA_F_STRING_ARGS;
				break;
			case 'b':
				ctx.flags |= SHIVA_F_JMP_CFLOW;
				break;
			case 'r':
				ctx.flags |= SHIVA_F_RETURN_FLOW;
				break;
			default:
				break;
			}
		}
	}
	shiva_debug("Target path: %s\n", ctx.path);
	shiva_debug("Target args: ");
#if DEBUG
	for (i = 0; i < ctx.argcount; i++) {
		printf("%s ", ctx.args[i]);
	}
#endif
	if (load_trace_data(&ctx) == false) {
		fprintf(stderr, "load_trace_data(%p) failed\n", &ctx);
		exit(EXIT_FAILURE);
	}
}
