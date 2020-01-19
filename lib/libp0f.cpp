
#include "p0f/libp0f.h"

libp0f_context_t::~libp0f_context_t() {
	process_context.destroy_all_hosts();
}

void libp0f_context_t::read_fingerprints(const char *filename) {
	fp_context.read_config(filename);
}
