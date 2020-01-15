/*
   p0f - a port of lookup3
   -----------------------

   The hash32() function is a modified copy of lookup3, a good non-cryptosafe
   seeded hashing function developed by Bob Jenkins.

   Bob's original code is public domain; so is this variant.

 */

#ifndef HAVE_HASH_H_
#define HAVE_HASH_H_

#include "types.h"

#define ROL32(_x, _r) (((_x) << (_r)) | ((_x) >> (32 - (_r))))

constexpr uint32_t hash32(const void *key, uint32_t len) {

	uint32_t seed = 0;

	uint32_t a = 0xdeadbeef + len + seed;
	uint32_t b = a;
	uint32_t c = a;

	auto k = static_cast<const uint8_t *>(key);

	while (len > 12) {

		a += RD32p(k);
		b += RD32p(k + 4);
		c += RD32p(k + 8);

		a -= c;
		a ^= ROL32(c, 4);
		c += b;
		b -= a;
		b ^= ROL32(a, 6);
		a += c;
		c -= b;
		c ^= ROL32(b, 8);
		b += a;
		a -= c;
		a ^= ROL32(c, 16);
		c += b;
		b -= a;
		b ^= ROL32(a, 19);
		a += c;
		c -= b;
		c ^= ROL32(b, 4);
		b += a;

		len -= 12;
		k += 12;
	}

	switch (len) {
	case 12:
		c += RD32p(k + 8);
		b += RD32p(k + 4);
		a += RD32p(k);
		break;

	case 11:
		c += (RD16p(k + 8) << 8) | k[10];
		b += RD32p(k + 4);
		a += RD32p(k);
		break;

	case 10:
		c += RD16p(k + 8);
		b += RD32p(k + 4);
		a += RD32p(k);
		break;

	case 9:
		c += k[8];
		b += RD32p(k + 4);
		a += RD32p(k);
		break;

	case 8:
		b += RD32p(k + 4);
		a += RD32p(k);
		break;

	case 7:
		b += (RD16p(k + 4) << 8) | k[6];
		a += RD32p(k);
		break;

	case 6:
		b += RD16p(k + 4);
		a += RD32p(k);
		break;

	case 5:
		b += k[4];
		a += RD32p(k);
		break;

	case 4:
		a += RD32p(k);
		break;

	case 3:
		a += (RD16p(k) << 8) | k[2];
		break;

	case 2:
		a += RD16p(k);
		break;

	case 1:
		a += k[0];
		break;

	case 0:
		return c;
	}

	c ^= b;
	c -= ROL32(b, 14);
	a ^= c;
	a -= ROL32(c, 11);
	b ^= a;
	b -= ROL32(a, 25);
	c ^= b;
	c -= ROL32(b, 16);
	a ^= c;
	a -= ROL32(c, 4);
	b ^= a;
	b -= ROL32(a, 14);
	c ^= b;
	c -= ROL32(b, 24);

	return c;
}

#endif
