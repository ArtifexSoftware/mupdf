/* multiply 8-bit fixpoint (0..1) so that 0*0==0 and 255*255==255 */
static inline unsigned char fz_mul255(unsigned char a, unsigned char b)
{
	return ((a + 1) * b) >> 8;
}

/* floor / ceil towards/from +/- inf */
static inline float fz_floor(float x)
{
	if (x > 0)
		return floor(x);
	return ceil(x);
}

static inline float fz_ceil(float x)
{
	if (x > 0)
		return ceil(x);
	return floor(x);
}

/* divide and floor towards -inf */
static inline int fz_idiv(int a, int b)
{
	return a < 0 ? (a - b + 1) / b : a / b;
}

/* from python */
static inline void fz_idivmod(int x, int y, int *d, int *m)
{
	int xdivy = x / y;
	int xmody = x - xdivy * y;
	/* If the signs of x and y differ, and the remainder is non-0,
	 * C89 doesn't define whether xdivy is now the floor or the
	 * ceiling of the infinitely precise quotient.  We want the floor,
	 * and we have it iff the remainder's sign matches y's.
	 */
	if (xmody && ((y ^ xmody) < 0)) {
		xmody += y;
		xdivy --;
	}
	*d = xdivy;
	*m = xmody;
}

