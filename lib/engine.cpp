
#include "p0f/engine.h"
#include "p0f/p0f.h"
#include "p0f/process.h"
#include "p0f/readfp.h"

engine::engine(const char *fp_database, libp0f_context_t *ctx)
	: ctx_(ctx) {

	ctx_->fp_context.read_config(fp_database);
}

engine::~engine() {
	ctx_->process_context.destroy_all_hosts();
}
