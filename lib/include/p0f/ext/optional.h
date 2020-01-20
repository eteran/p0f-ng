
#ifndef P0F_EXT_OPTIONAL_H_
#define P0F_EXT_OPTIONAL_H_

#include <boost/optional.hpp>

namespace ext {

template <class T>
using optional = boost::optional<T>;

}

#endif
