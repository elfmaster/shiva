/*
 * Fuzz the LDSO via modifications to PT_DYNAMIC
 * and relocation tables, etc.
 */

#include "../shiva.h"

#define MAX_DT_VALUE 30

int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	struct elf_segment phdr;
	size_t dcount;
	uint32_t v, b;
	struct timeval tv;
	shiva_auxv_iterator_t a_iter;
	struct shiva_auxv_entry a_entry;
	uint64_t tag_value, highest_vaddr, rand_val;

	printf("LDSO-FUZZ v0.1 (Shiva runtime engine)\n");
	printf("&ctx->elfobj: %p\n", &ctx->elfobj);
	if (elf_segment_by_p_type(&ctx->elfobj, PT_DYNAMIC, &phdr) == false) {
		printf("Cannot find dynamic segment\n");
		exit(-1);
	}
	dcount = phdr.filesz / sizeof(Elf64_Dyn);
	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	/*
	 * Let's only provide values as high as the executable address space
	 * goes, in some instances. In other instances we will send a random
	 * uint64_t
	 */
	highest_vaddr = elf_data_base(&ctx->elfobj) + elf_data_filesz(&ctx->elfobj);
	gettimeofday(NULL, &tv);
	srand(tv.tv_usec);
	while (1) {
		rand_val = (tag_value % 2 == 0) ? (rand() & (highest_vaddr - 1)) :
		    rand() & ~(uint64_t)0ULL;
		gettimeofday(&tv, NULL);
		srand(tv.tv_usec);
		tag_value = rand() & (MAX_DT_VALUE - 1);
		if (shiva_target_dynamic_set(ctx, tag_value, rand_val) == true)
			break;
	}

	printf("Set DTAG %d with %#lx\n", tag_value, rand_val);
	/*
	 * Hook the AT_ENTRY value so that it points back to our module after
	 * LDSO is done. Only use the auxiliary vector created
	 * by the userland-exec, since this is the one that is being passed
	 * to LDSO.
	 */
	if (shiva_auxv_iterator_init(ctx, &a_iter,
	    ctx->ulexec.auxv.vector) == false) {
		printf("shiva_auxv_iterator_init failed\n");
		exit(-1);
	}
	while (shiva_auxv_iterator_next(&a_iter, &a_entry) == SHIVA_ITER_OK) {
		if (a_entry.type == AT_ENTRY) {
			uint64_t entry;

			/*
			 * This isn't an API function but we will call into
			 * it illegaly (It's in shiva_module.c, the linker code).
			 */
			if (module_entrypoint(ctx->module.runtime, &entry) == false) {
				printf("couldn't find module entrypoint, exiting...\n");
				exit(-1);
			}
			/*
			 * Set AT_ENTRY to the entry point of our module. (Normally
			 * it points to the target program, of course).
			 */
			if (shiva_auxv_set_value(&a_iter, entry) == false) {
				printf("shiva_auxv_set_value failed (Setting %#lx)\n", entry);
				exit(-1);
			}
			printf("Set AT_ENTRY = %#lx\n", entry);
		}
	}
	printf("Returning from module\n");
	return 0;
}

