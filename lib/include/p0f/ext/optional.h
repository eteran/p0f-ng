
#ifndef OPTIONAL_H_
#define OPTIONAL_H_

#include <boost/optional.hpp>

namespace ext {

template <class T>
using optional = boost::optional<T>;

}

#endif
