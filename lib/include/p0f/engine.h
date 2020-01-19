
#ifndef ENGINE_H_
#define ENGINE_H_

struct libp0f_context_t;

class engine {
public:
	engine(libp0f_context_t *ctx);
	~engine();

public:
	void read_fingerprints(const char *filename);

private:
	libp0f_context_t *ctx_ = nullptr;
};

#endif
