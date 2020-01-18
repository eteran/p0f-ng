
#include "p0f/engine.h"
#include "p0f/process.h"
#include "p0f/readfp.h"

engine::engine(const char *fp_database) {
	read_config(fp_database);
}

engine::~engine() {
	destroy_all_hosts();
}
