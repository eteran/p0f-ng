
#include "p0f/parser.h"

/**
 * @brief parser::Input
 * @param source
 * @param input
 */
parser::parser(string_view input)
	: input_(input) {
}

/**
 * @brief parser::peek
 * @return
 */
char parser::peek() const {

	if (eof()) {
		return '\0';
	}

	return input_[index_];
}

/**
 * @brief parser::read
 * @return
 */
char parser::read() {

	if (eof()) {
		return '\0';
	}

	char ch = input_[index_++];

	switch (ch) {
	case '\n':
		++line_;
		column_ = 0;
		break;
	default:
		++column_;
	}

	return ch;
}

/**
 * @brief parser::eof
 * @return
 */
bool parser::eof() const {
	return index_ == input_.size();
}

/**
 * @brief parser::consume
 * @param chars
 */
void parser::consume(string_view chars) {

	while (!eof()) {
		char ch = peek();

		if (chars.find(ch) == std::string::npos) {
			break;
		}

		read();
	}
}

/**
 * @brief parser::match_any
 * @param match
 * @return
 */
bool parser::match_any(std::string *match) {
	std::string m;
	while (!eof()) {
		m.push_back(read());
	}

	if (!m.empty()) {
		*match = m;
		return true;
	}

	return false;
}

/**
 * @brief parser::match_any_of
 * @param chars
 * @param match
 * @return
 */
bool parser::match_any_of(string_view chars, std::string *match) {
	std::string m;
	while (true) {
		const char ch = peek();
		if (chars.find(ch) == std::string::npos) {
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

/**
 * @brief parser::match
 * @param s
 * @return
 */
bool parser::match(string_view s) {

	if (index_ + s.size() > input_.size()) {
		return false;
	}

	for (size_t i = 0; i < s.size(); ++i) {
		if (input_[index_ + i] != s[i]) {
			return false;
		}
	}

	column_ += s.size();
	index_ += s.size();
	return true;
}

/**
 * @brief parser::match
 * @param ch
 * @return
 */
bool parser::match(char ch) {

	if (peek() != ch) {
		return false;
	}

	if (ch == '\n') {
		column_ = 0;
		++line_;
	} else {
		++column_;
	}

	++index_;
	return true;
}

/**
 * @brief parser::index
 * @return
 */
size_t parser::index() const {
	return index_;
}

/**
 * @brief parser::line
 * @return
 */
size_t parser::line() const {
	return line_;
}

/**
 * @brief parser::column
 * @return
 */
size_t parser::column() const {
	return column_;
}
