
#ifndef READER_H_
#define READER_H_

#if __cplusplus >= 201703L
#include <optional>
#include <string_view>
#else
#include <boost/optional.hpp>
#include <boost/utility/string_view.hpp>
#endif

#include <cstddef>
#include <regex>
#include <string>

class Reader {
public:
#if __cplusplus >= 201703L
	using string_view = std::string_view;

	template <class T>
	using optional = std::optional<T>;
#else
	using string_view = boost::string_view;

	template <class T>
	using optional = boost::optional<T>;

#endif

public:
	Reader() = default;
	explicit Reader(string_view input) noexcept;
	Reader(const Reader &other) = default;
	Reader &operator=(const Reader &rhs) = default;
	~Reader()                            = default;

public:
	bool eof() const noexcept;
	char peek() const noexcept;
	char read() noexcept;
	size_t consume(string_view chars) noexcept;
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
	bool match(string_view s) noexcept;
	optional<std::string> match_any();

	optional<std::string> match(const std::regex &regex);

	template <class Pred>
	optional<std::string> match_while(Pred pred) {
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
	size_t line() const noexcept;
	size_t column() const noexcept;

private:
	string_view input_;
	size_t index_  = 0;
	size_t line_   = 1;
	size_t column_ = 1;
};

#endif
