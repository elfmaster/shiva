#include "shiva.h"

bool
shiva_trace_op_attach(struct shiva_ctx *ctx, pid_t pid, shiva_trace_op_t op,
    void *addr, void *data)
{
	bool res;

	(void)op;

	if (pid == 0) {
		res = shiva_trace_thread_insert(ctx, pid);
		if (res == false) {
			fprintf(stderr, "attach pid(%d) failed: Unknown error\n", pid);
			return false;
		}
	} else {
		/*
		 * TODO for multiple threads
		 */
	}
	return true;
}

/*
 * shiva_trace_op_t types:
 * SHIVA_TRACE_OP_ATTACH
 * SHIVA_TRACE_OP_CONT
 * SHIVA_TRACE_OP_POKE
 * SHIVA_TRACE_OP_PEEK
 * SHIVA_TRACE_OP_GETREGS
 * SHIVA_TRACE_OP_SETREGS
 * SHIVA_TRACE_OP_SETFPREGS
 * SHIVA_TRACE_OP_GETSIGINFO
 * SHIVA_TRACE_OP_SETSIGINFO
 */

bool
shiva_trace(struct shiva_ctx *ctx, pid_t pid, shiva_trace_op_t op,
    void *addr, void *data)
{
	bool res;

	switch(op) {
	case SHIVA_TRACE_OP_ATTACH:
		res = shiva_trace_op_attach(ctx, pid, op, addr, data);
		break;
#if 0
	case SHIVA_TRACE_OP_CONT:
		res = shiva_trace_op_cont(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_POKE:
		res = shiva_trace_op_cont(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_PEEK:
		res = shiva_trace_op_cont(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_GETREGS:
		res = shiva_trace_op_getregs(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_SETREGS:
		res = shiva_trace_op_setregs(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_GETSIGINFO:
		res = shiva_trace_op_getsiginfo(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_SETSIGINFO:
		res = shiva_trace_op_setsiginfo(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_SETFPREGS:
		res = shiva_trace_op_setfpregs(ctx, pid, op, addr, data);
		break;
#endif
	default:
		break;
	}
	return res;
}