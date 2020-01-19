
#include "p0f/engine.h"
#include "p0f/p0f.h"
#include "p0f/process.h"
#include "p0f/readfp.h"

engine::engine(libp0f_context_t *ctx)
	: ctx_(ctx) {
}

engine::~engine() {
	ctx_->process_context.destroy_all_hosts();
}

void engine::read_fingerprints(const char *filename) {
	ctx_->fp_context.read_config(filename);
}
