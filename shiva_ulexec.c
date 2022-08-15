#include "shiva.h"

#define SHIVA_AUXV_COUNT 19

uint8_t *
shiva_ulexec_allocstack(struct shiva_ctx *ctx)
{
	ctx->ulexec.stack = mmap(NULL, SHIVA_STACK_SIZE, PROT_READ|PROT_WRITE,
	    MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_32BIT, -1, 0);
	assert(ctx->ulexec.stack != MAP_FAILED);
	shiva_debug("STACK: %#lx - %#lx\n", (uint64_t)ctx->ulexec.stack,
	    (uint64_t)ctx->ulexec.stack + (size_t)SHIVA_STACK_SIZE);
	return (ctx->ulexec.stack + SHIVA_STACK_SIZE);
}
/*
 * Remember the layout:
 *	argc, argv[0], argv[N], NULL, envp[0], envp[N], auxv_entry[0], auxv_entry[N], .ascii data
 *		   \______________________________________________________________________/
 *
 */

static bool
shiva_ulexec_build_auxv_stack(struct shiva_ctx *ctx, uint64_t *out, Elf64_auxv_t **auxv_ptr)
{
	uint64_t *esp;
	uint64_t esp_start;
	int i, totalsize, len, argc;
	uint8_t *stack;
	char *strdata, *s;
	shiva_auxv_iterator_t a_iter;
	struct shiva_auxv_entry a_entry;
	size_t count = 0;

	count += sizeof(argc);
	count += ctx->argc * sizeof(char *);
	count += sizeof(void *);
	count += ctx->ulexec.envpcount * sizeof(char *);
	count += sizeof(void *);
	count += (SHIVA_AUXV_COUNT + 1) * sizeof(Elf64_auxv_t);
	count = (count + 16) & ~(16 - 1);
	totalsize = count + ctx->ulexec.envplen + ctx->ulexec.arglen;
	totalsize = (totalsize + 16) & ~(16 - 1);

	stack = shiva_ulexec_allocstack(ctx);
	if (stack == NULL) {
		fprintf(stderr, "Unable to allocate stack\n");
		return false;
	}
	shiva_debug("STACK: %p\n", stack);
	esp = (uint64_t *)stack;
	esp = esp - (totalsize / sizeof(void *));
	esp_start = (uint64_t)esp;
	/*
	 * strdata points to the end of the auxiliary vector
	 * where it must copy the ascii data into place. This
	 * data was copied into ctx->ulexec.argstr earlier in
	 * the shiva_ulexec_save_stack() function.
	 */
	strdata = (char *)(esp_start + count);
	s = ctx->ulexec.argstr;
	*esp++ = ctx->argc;
	for (argc = ctx->argc; argc > 0; argc--) {
		strcpy(strdata, s);
		len = strlen(s) + 1;
		s += len;
		*esp++ = (uintptr_t)strdata; /* set argv[n] = (char *)"arg_string" */
		strdata += len;
	}
	/*
	 * Append NULL after last argv ptr
	 */
	*esp++ = (uintptr_t)0; // Our stack currently: argc, argv[0], argv[n], NULL
	/*
	 * Copyin envp pointers and envp ascii data
	 */
	for (s = ctx->ulexec.envstr, i = 0; i < ctx->ulexec.envpcount; i++) {
		strcpy(strdata, s);
		len = strlen(s) + 1;
		s += len;
		*esp++ = (uintptr_t)strdata;
		strdata += len;
	}
	*esp++ = (uintptr_t)0;

	Elf64_auxv_t *auxv = (Elf64_auxv_t *)esp;
	*auxv_ptr = auxv;
	shiva_auxv_iterator_init(ctx, &a_iter, NULL);
	while (shiva_auxv_iterator_next(&a_iter, &a_entry) == SHIVA_ITER_OK) {
		auxv->a_type = a_entry.type;
		switch(a_entry.type) {
		case AT_PHDR:
			auxv->a_un.a_val = ctx->ulexec.phdr_vaddr;
			break;
		case AT_PHNUM:
			auxv->a_un.a_val = elf_segment_count(&ctx->elfobj);
			break;
		case AT_BASE:
			auxv->a_un.a_val = ctx->ulexec.ldso.base_vaddr;
			break;
		case AT_ENTRY:
			auxv->a_un.a_val = ctx->ulexec.entry_point;
			break;
		case AT_FLAGS:
			/*
			 * SPECIAL NOTE: We overwrite the flags entry with
			 * a saved pointer to the shiva_ctx_t *ctx. This is
			 * then passed into %rdi before calling the module
			 * code.
			 */
			//auxv->a_un.a_val = (uint64_t)ctx;
		default:
			auxv->a_un.a_val = a_entry.value;
			break;
		}
		auxv++;
	}
	auxv->a_type = AT_NULL;
	/*
	 * Set the out value to the stack address that is &argc -- the beginning
	 * of our stack setup.
	 */
	*out = (uint64_t)esp_start;
	return esp_start;
}

static bool
shiva_ulexec_save_stack(struct shiva_ctx *ctx)
{
	size_t sz, i, j, tmp;
	char **envpp = ctx->envp;
	char *s;

	for (i = 0, sz = 0, tmp = ctx->argc; tmp > 0; tmp--, i++)
		sz += strlen(ctx->argv[i]) + 1;
	ctx->ulexec.arglen = sz;

	for (i = 0, sz = 0; *envpp != NULL; envpp++, i++)
		sz += strlen(*envpp) + 1;

	ctx->ulexec.envpcount = i;
	ctx->ulexec.envplen = sz;
	ctx->ulexec.envstr = malloc(ctx->ulexec.envplen);
	if (ctx->ulexec.envstr == NULL) {
		perror("malloc");
		return false;
	}
	ctx->ulexec.argstr = malloc(ctx->ulexec.arglen);
	if (ctx->ulexec.argstr == NULL) {
		perror("malloc");
		return false;
	}
	for (s = ctx->ulexec.argstr, j = 0, i = 0; i < ctx->argc; i++) {
		shiva_debug("Copying bytes from %s\n", ctx->argv[i]);
		while (j < strlen(ctx->argv[i])) {
			s[j] = ctx->argv[i][j];
			j++;
		}
		s[j] = '\0';
		s += strlen(ctx->argv[i]) + 1;
		j = 0;
	}
	for (i = 0; *ctx->envp != NULL; ctx->envp++) {
		strcpy(&ctx->ulexec.envstr[i], *ctx->envp);
		i += strlen(*ctx->envp) + 1;
	}
	return true;
}

static inline int
shiva_ulexec_make_prot(uint32_t p_flags)
{
	int prot = 0;

	if (p_flags & PF_R)
		prot |= PROT_READ;
	if (p_flags & PF_W)
		prot |= PROT_WRITE;
	if (p_flags & PF_X)
		prot |= PROT_EXEC;
	return prot;
}

/*
 * Copy p_filesz bytes of the PT_LOAD segment (3rd arg) into
 * the buffer specified by dst (2nd arg).
 */
static bool
shiva_ulexec_segment_copy(elfobj_t *elfobj, uint8_t *dst,
    struct elf_segment segment)
{
	size_t rem = segment.filesz % sizeof(uint64_t);
	uint64_t qword;
	bool res;
	size_t i = 0;

	shiva_debug("Remainder: %d bytes\n", rem);
	shiva_debug("Reading from address %#lx - %#lx\n", segment.vaddr,
	    segment.vaddr + segment.filesz);
	for (i = 0; i < segment.filesz; i += sizeof(uint64_t)) {
		if (i + sizeof(uint64_t) >= segment.filesz) {
			size_t j;

			for (j = 0; j < rem; j++) {
				res = elf_read_address(elfobj, segment.vaddr + i + j,
				    &qword, ELF_BYTE);
				if (res == false) {
					shiva_debug("shiva_ulexec_segment_copy "
					    "failed at %#lx\n", segment.vaddr + i + j);
					return false;
				}
				dst[i + j] = (uint8_t)qword;
			}
			break;
		}
		res = elf_read_address(elfobj, segment.vaddr + i, &qword, ELF_QWORD);
		if (res == false) {
			shiva_debug("elf_read_address failed at %#lx\n", segment.vaddr + i);
			return false;
		}
		*(uint64_t *)&dst[i] = qword;
	}
	return true;
}

/*
 * XXX -- We currently only support PIE binaries. This is very temporary.
 */
bool
shiva_ulexec_load_elf_binary(struct shiva_ctx *ctx, elfobj_t *elfobj, bool interpreter)
{
	bool res;
	elf_iterator_res_t ires;
	elf_segment_iterator_t phdr_iter;
	struct elf_segment phdr;
	uint64_t load_addr;
	uint64_t base_vaddr;
	uint8_t *mem;
	size_t memsz;
	int fd = elf_fd(elfobj);

	elf_segment_iterator_init(elfobj, &phdr_iter);
	for (;;) {
		uint32_t elfprot;

		ires = elf_segment_iterator_next(&phdr_iter, &phdr);
		if (ires == ELF_ITER_DONE)
			break;
		if (ires == ELF_ITER_ERROR)
			return false;
		if (phdr.type != PT_LOAD)
			continue;
		elfprot = shiva_ulexec_make_prot(phdr.flags);
		if (elfprot & PROT_READ)
			shiva_debug("PROT_READ\n");
		if (elfprot & PROT_WRITE)
			shiva_debug("PROT_WRITE\n");
		if (elfprot & PROT_EXEC)
			shiva_debug("PROT_EXEC\n");
		int mmap_flags = MAP_PRIVATE;
		mmap_flags |= !(ctx->flags & SHIVA_OPTS_F_INTERP_MODE) ? MAP_FIXED : 0;
		if (interpreter == true) {
			/*
			 * NOTE: SHIVA_OPTS_F_INTERP_MODE flag indicates whether or not
			 * Shiva is executing as an interpreter. If it's being run as an
			 * interpreter we want base_vaddr to be set to 0. Otherwise if Shiva
			 * is executing directly then we want to set a specific base address
			 * for the RTLD and for the target executable. SHIVA_LDSO_BASE or
			 * SHIVA_TARGET_BASE.
			 */
			base_vaddr = !(ctx->flags & SHIVA_OPTS_F_INTERP_MODE) ? SHIVA_LDSO_BASE : 0;
		} else {
			base_vaddr = !(ctx->flags & SHIVA_OPTS_F_INTERP_MODE) ? SHIVA_TARGET_BASE : 0;
		}
		if (phdr.offset == 0) {
			shiva_debug("Attempting to map %#lx\n", base_vaddr);
			mem = mmap((void *)base_vaddr, phdr.memsz, elfprot, mmap_flags, fd, 0);
			if (mem == MAP_FAILED) {
				perror("mmap");
				exit(EXIT_FAILURE);
			}
			base_vaddr = (uint64_t)mem;
#if 0
			//mem = (uint8_t *)base_vaddr;
			res = shiva_ulexec_segment_copy(elfobj, mem, phdr);
			if (res == false) {
				shiva_debug("shiva_ulexec_segment_copy(%p, %p, %p) failed\n",
				    elfobj, mem, &phdr);
				return false;
			}
			if (mprotect(mem,
			    (phdr.memsz + 4095) & ~4095, elfprot) < 0) {
				shiva_debug("mprotect: %s\n", strerror(errno));
				return false;
			}
#endif
			continue;
		}
		load_addr = base_vaddr + phdr.vaddr;
		load_addr = ELF_PAGESTART(load_addr);
		shiva_debug("Mapping segment: %#lx of size %zu\n", load_addr, phdr.memsz);
		memsz = phdr.memsz;
		if (phdr.flags == (PF_R|PF_W)) {
			/*
			 * If this is the data segment map enough room for
			 * the .bss segment.
			 */
			memsz = ELF_PAGEALIGN(phdr.memsz, 0x1000) +
			    ELF_PAGEALIGN(phdr.memsz - phdr.filesz, 0x1000);
		}
		mem = mmap((void *)load_addr, memsz,
		    elfprot, mmap_flags, fd, 
		    phdr.offset - ELF_PAGEOFFSET(phdr.vaddr));
		if (mem == MAP_FAILED) {
			shiva_debug("mmap failed: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
#if 0
		shiva_ulexec_segment_copy(elfobj, &mem[phdr.vaddr & (PAGE_SIZE - 1)], phdr);
		if (mprotect(mem, (phdr.memsz + 4095) & ~4095,
		    elfprot) < 0) {
			shiva_debug("mprotect: %s\n", strerror(errno));
			return false;
		}
#endif
	}
	if (interpreter == false) {
		shiva_debug("Setting entry point for target: %#lx\n", base_vaddr + elf_entry_point(elfobj));
		ctx->ulexec.entry_point = base_vaddr + elf_entry_point(elfobj);
		ctx->ulexec.base_vaddr = base_vaddr;
		ctx->ulexec.phdr_vaddr = base_vaddr + elf_phoff(elfobj);
	} else {
		shiva_debug("Setting entry point for ldso: %#lx\n", base_vaddr + elf_entry_point(elfobj));
		ctx->ulexec.ldso.entry_point = base_vaddr + elf_entry_point(elfobj);
		ctx->ulexec.ldso.base_vaddr = base_vaddr;
		ctx->ulexec.ldso.phdr_vaddr = base_vaddr + elf_phoff(elfobj);
	}
	return true;
}

bool
shiva_ulexec_prep(struct shiva_ctx *ctx)
{
	char *interp = NULL;
	elf_error_t error;
	shiva_auxv_iterator_t a_iter;
	struct shiva_auxv_entry a_entry;

	if (elf_type(&ctx->elfobj) == ET_DYN) {
		interp = elf_interpreter_path(&ctx->elfobj);
		if (interp != NULL) {
			shiva_debug("Interp path: %s\n", interp);
			ctx->ulexec.flags |= SHIVA_F_ULEXEC_LDSO_NEEDED;
			if (elf_open_object(interp, &ctx->ldsobj, ELF_LOAD_F_STRICT, &error)
			    == false) {
				fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
				    interp, elf_error_msg(&error));
				return false;
			}
		}
	}
	shiva_debug("Loading ELF binary: %s\n", elf_pathname(&ctx->elfobj));
	if (shiva_ulexec_load_elf_binary(ctx, &ctx->elfobj, false) == false) {
		fprintf(stderr, "shiva_ulexec_load_elf_binary(%p, %s, false) failed\n",
		    ctx, elf_pathname(&ctx->elfobj));
		return false;
	}
	if (ctx->ulexec.flags & SHIVA_F_ULEXEC_LDSO_NEEDED) {
		shiva_debug("Loading LDSO: %s\n", elf_pathname(&ctx->ldsobj));
		if (shiva_ulexec_load_elf_binary(ctx, &ctx->ldsobj, true) == false) {
			fprintf(stderr, "shiva_ulexec_load_elf_binary(%p, %s, true) failed\n",
			    ctx, elf_pathname(&ctx->ldsobj));
			    return false;
		}
	}
	shiva_debug("Saving stack data from &argc foward\n");
	if (shiva_ulexec_save_stack(ctx) == false) {
		fprintf(stderr, "shiva_ulexec_save_stack() failed\n");
		return false;
	}

	shiva_debug("Building auxiliary vector\n");
	if (shiva_ulexec_build_auxv_stack(ctx, &ctx->ulexec.rsp_start,
	    (Elf64_auxv_t **)&ctx->ulexec.auxv.vector) == false) {
		fprintf(stderr, "shiva_ulexec_build_auxv_stack() failed\n");
		return false;
	}
	shiva_auxv_iterator_init(ctx, &a_iter, ctx->ulexec.auxv.vector);
	while (shiva_auxv_iterator_next(&a_iter, &a_entry) == SHIVA_ITER_OK) {
		printf("AUXV TYPE: %d AUXV VAL: %#lx\n", a_entry.type, a_entry.value);
	}

#if 0
	prctl(PR_SET_MM, PR_SET_MM_AUXV, (unsigned long)ctx->ulexec.auxv.vector,
	    20);
#endif

	return true;
}
