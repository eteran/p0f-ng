
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
	Reader(){};
	explicit Reader(string_view input);
	Reader(const Reader &other) = default;
	Reader &operator=(const Reader &rhs) = default;
	~Reader()                            = default;

public:
	bool eof() const;
	char peek() const;
	char read();
	void consume(string_view chars);
	void consume_whitespace();

	template <class Pred>
	void consume_while(Pred pred) {
		while (!eof()) {
			char ch = peek();

			if (!pred(ch)) {
				break;
			}

			read();
		}
	}

	bool match(char ch);
	bool match(string_view s);
	optional<std::string> match_any();

	optional<std::string> match(const std::regex &regex);

	template <class Pred>
	optional<std::string> match_if(Pred pred) {
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

	size_t index() const;
	size_t line() const;
	size_t column() const;

private:
	string_view input_;
	size_t index_  = 0;
	size_t line_   = 1;
	size_t column_ = 1;
};

#endif
