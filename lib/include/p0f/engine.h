
#ifndef ENGINE_H_
#define ENGINE_H_

struct libp0f_context_t;

class engine {
public:
	engine(const char *fp_database, libp0f_context_t *ctx);
	~engine();

private:
	libp0f_context_t *ctx_ = nullptr;
};

#endif
