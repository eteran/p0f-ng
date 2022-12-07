
#ifndef READER_H_
#define READER_H_

#include <cstddef>
#include <optional>
#include <regex>
#include <stack>
#include <string>
#include <string_view>

class Reader {
public:
	struct Location {
		size_t line;
		size_t column;
	};

public:
	Reader() = default;
	explicit Reader(std::string_view input) noexcept;
	Reader(const Reader &other)          = default;
	Reader &operator=(const Reader &rhs) = default;
	~Reader()                            = default;

public:
	bool eof() const noexcept;
	char peek() const noexcept;
	char read() noexcept;
	size_t consume(std::string_view chars) noexcept;
	size_t consume_whitespace() noexcept;

	template <class Pred>
	size_t consume_while(Pred pred) noexcept {
		size_t count = 0;
		while (!eof()) {
			char ch = peek();

			if (!pred(ch)) {
				break;
			}

			read();
			++count;
		}
		return count;
	}

	bool match(char ch) noexcept;
	bool match(std::string_view s) noexcept;
	std::optional<std::string> match_any();

	std::optional<std::string> match(const std::regex &regex);

	template <class Pred>
	std::optional<std::string> match_while(Pred pred) {
		std::string m;
		while (!eof()) {
			const char ch = peek();
			if (!pred(ch)) {
				break;
			}
			m.push_back(read());
		}

		if (!m.empty()) {
			return m;
		}

		return {};
	}

	size_t index() const noexcept;
	Location location() const noexcept;
	Location location(size_t index) const noexcept;

	void push_state();
	void pop_state();
	void restore_state();

private:
	std::string_view input_;
	size_t index_ = 0;
	std::stack<size_t> state_;
};

#endif
