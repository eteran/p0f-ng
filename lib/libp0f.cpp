
#include "p0f/libp0f.h"

libp0f::~libp0f() {
	process_context.destroy_all_hosts();
}

void libp0f::read_fingerprints(const char *filename) {
	fp_context.read_config(filename);
}

void libp0f::begin_observation(const char *keyword, uint8_t field_cnt, bool to_srv, const packet_flow *f) {
	start_observation(process_context.get_unix_time(), keyword, field_cnt, to_srv, f);
}
