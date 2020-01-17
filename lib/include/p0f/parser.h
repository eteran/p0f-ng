
#ifndef PARSER_H_
#define PARSER_H_

#include "ext/string_view.h"
#include <cstddef>
#include <string>

class parser {
public:
	explicit parser(ext::string_view input);

public:
	bool eof() const;
	char peek() const;
	char read();
	void consume(ext::string_view chars);
	bool match(char ch);
	bool match(ext::string_view s);
	bool match_any(std::string *match);

	template <class Pred>
	bool match(Pred pred, std::string *match) {
		std::string m;
		while (!eof()) {
			const char ch = peek();
			if (!pred(ch)) {
				break;
			}
			m.push_back(read());
		}

		if (!m.empty()) {
			*match = m;
			return true;
		}

		return false;
	}

	size_t index() const;
	size_t line() const;
	size_t column() const;

private:
	ext::string_view input_;
	size_t index_  = 0;
	size_t line_   = 1;
	size_t column_ = 1;
};

#endif
