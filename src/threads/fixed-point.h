#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include "stdint.h"

#define P 17
#define Q 14
#define F (1 << Q)

#define fixed int32_t

#define to_fixed(n) (n) * (F)
#define to_int_to_zero(x) x / F
#define to_int_to_nearest(x) x >= 0 ? (x + (F / 2)) / F : (x - (F / 2)) / F

#define add_fixed(x, y) x + y
#define sub_fixed(x, y) x - y
#define mul_fixed(x, y) (fixed)((int64_t)(x) * (y) / F)
#define div_fixed(x, y) (fixed)((int64_t)(x) * (F) / y)

#define add_int(x, n) x + ((n) * (F))
#define sub_int(x, n) x - ((n) * (F))
#define mul_int(x, n) (x) * (n)
#define div_int(x, n) x / n

#endif /* threads/fixed-point.h */
