
#ifndef PARSER_H_
#define PARSER_H_

#include "string_view.h"
#include <cstddef>
#include <string>

class parser {
public:
	explicit parser(std::string input);

public:
	bool eof() const;
	char peek() const;
	char read();
	void consume(string_view chars);
	bool match(char ch);
	bool match(string_view s);
	bool match_any_of(string_view chars, std::string *match);
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
	std::string input_; // TODO(eteran): would be better as string_view
	size_t index_  = 0;
	size_t line_   = 1;
	size_t column_ = 1;
};

#endif
