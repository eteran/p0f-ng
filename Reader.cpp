
#include "Reader.h"

/**
 * @brief Reader::Reader
 * @param input
 */
Reader::Reader(std::string_view input) noexcept
	: input_(input) {
}

/**
 * @brief Reader::peek
 * @return
 */
char Reader::peek() const noexcept {

	if (eof()) {
		return '\0';
	}

	return input_[index_];
}

/**
 * @brief Reader::read
 * @return
 */
char Reader::read() noexcept {

	if (eof()) {
		return '\0';
	}

	return input_[index_++];
}

/**
 * @brief Reader::eof
 * @return
 */
bool Reader::eof() const noexcept {
	return index_ == input_.size();
}

/**
 * @brief Reader::consume
 * @param chars
 */
size_t Reader::consume(std::string_view chars) noexcept {

	// consume while the next character is in the input set
	return consume_while([chars](char ch) {
		return chars.find(ch) != std::string::npos;
	});
}

/**
 * @brief Reader::consume_whitespace
 */
size_t Reader::consume_whitespace() noexcept {

	// consume while the next character is whitespace
	return consume_while([](char ch) {
		return (ch == ' ' || ch == '\t');
	});
}

/**
 * @brief Reader::match_any
 * @param match
 * @return
 */
auto Reader::match_any() -> std::optional<std::string> {
	std::string m;
	while (!eof()) {
		m.push_back(read());
	}

	if (!m.empty()) {
		return m;
	}

	return {};
}

/**
 * @brief Reader::match
 * @param regex
 * @return
 */
auto Reader::match(const std::regex &regex) -> std::optional<std::string> {

	std::cmatch matches;

	const char *first = &input_[index_];
	const char *last  = &input_[input_.size()];

	if (std::regex_search(first, last, matches, regex, std::regex_constants::match_continuous)) {
		std::string m = std::string(matches[0].first, matches[0].second);
		index_ += m.size();
		return m;
	}

	return {};
}

/**
 * @brief Reader::match
 * @param s
 * @return
 */
bool Reader::match(std::string_view s) noexcept {

	if (index_ + s.size() > input_.size()) {
		return false;
	}

	size_t new_index_ = index_ + s.size();

	for (size_t i = 0; i < s.size(); ++i) {
		const char ch = input_[index_ + i];
		if (ch != s[i]) {
			return false;
		}
	}

	index_ = new_index_;
	return true;
}

/**
 * @brief Reader::match
 * @param ch
 * @return
 */
bool Reader::match(char ch) noexcept {

	if (peek() != ch) {
		return false;
	}

	++index_;
	return true;
}

/**
 * @brief Reader::index
 * @return
 */
size_t Reader::index() const noexcept {
	return index_;
}

/**
 * @brief Reader::location
 *
 * @param index
 * @return Reader::Location
 */
Reader::Location Reader::location(size_t index) const noexcept {
	size_t line = 1;
	size_t col  = 1;

	if (index < input_.size()) {

		for (int i = 0; i < index; ++i) {
			if (input_[i] == '\n') {
				++line;
				col = 1;
			} else {
				++col;
			}
		}
	}

	return Location{line, col};
}

/**
 * @brief Reader::location
 *
 * @return Reader::Location
 */
Reader::Location Reader::location() const noexcept {
	return location(index_);
}
