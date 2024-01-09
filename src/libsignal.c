# include <string.h>
# include <stdint.h>
# include <openssl/sha.h>
# include <openssl/rand.h>
# include "lpc_ext.h"

# define CRYPTO_NAMESPACE(s)	ed25519_##s

# include "ref10/fe_0.c"
# include "ref10/fe_1.c"
# include "ref10/fe_add.c"
# include "ref10/fe_cmov.c"
# include "ref10/fe_copy.c"
# include "ref10/fe_frombytes.c"
# include "ref10/fe_invert.c"
# include "ref10/fe_isnegative.c"
# include "ref10/fe_isnonzero.c"
# include "ref10/fe_mul.c"
# include "ref10/fe_neg.c"
# include "ref10/fe_pow22523.c"
# include "ref10/fe_sq.c"
# include "ref10/fe_sq2.c"
# include "ref10/fe_sub.c"
# include "ref10/fe_tobytes.c"

# include "ref10/ge_add.c"
# include "ref10/ge_double_scalarmult.c"
# include "ref10/ge_frombytes.c"
# include "ref10/ge_madd.c"
# include "ref10/ge_msub.c"
# include "ref10/ge_p1p1_to_p2.c"
# include "ref10/ge_p1p1_to_p3.c"
# include "ref10/ge_p2_0.c"
# include "ref10/ge_p2_dbl.c"
# include "ref10/ge_p3_0.c"
# include "ref10/ge_p3_dbl.c"
# include "ref10/ge_p3_to_cached.c"
# include "ref10/ge_p3_to_p2.c"
# include "ref10/ge_p3_tobytes.c"
# include "ref10/ge_precomp_0.c"
# include "ref10/ge_sub.c"
# include "ref10/ge_tobytes.c"
# define select ge_scalarmult_base_select
# include "ref10/ge_scalarmult_base.c"

# define load_3 sc_muladd_load_3
# define load_4 sc_muladd_load_4
# include "ref10/sc_muladd.c"
# undef load_4
# undef load_3
# define load_3 sc_reduce_load_3
# define load_4 sc_reduce_load_4
# include "ref10/sc_reduce.c"


/*
 * y = (u - 1) / (u + 1)
 */
static int convert_mont(unsigned char *P, unsigned char *pk)
{
    fe u, one, um1, up1, y;

    fe_frombytes(u, pk);
    fe_1(one);
    fe_add(up1, u, one);
    if (!fe_isnonzero(up1)) {
	return 0;
    }
    fe_invert(up1, up1);
    fe_sub(um1, u, one);
    fe_mul(y, um1, up1);
    fe_tobytes(P, y);

    return 1;
}

/*
 * A = aB
 */
static void calculate_public_key(unsigned char *A, const unsigned char *a)
{
    ge_p3 E;

    ge_scalarmult_base(&E, a);
    ge_p3_tobytes(A, &E);
}

/*
 * A = calculate_public_key(a)
 * r = hash1(a || M || Z) (mod q)
 * R = rB
 * h = hash(R || A || M) (mod q)
 * s = r + ha (mod q)
 * return R || s
 */
static void xeddsa_sign(unsigned char *sm, const unsigned char *M, int len,
			const unsigned char *a, const unsigned char *Z)
{
    unsigned char A[32];
    unsigned char r[64];
    unsigned char h[64];
    EVP_MD_CTX *ctx;
    int i;
    ge_p3 R;

    calculate_public_key(A, a);

    ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    sm[0] = 0xfe;
    for (i = 1; i < 32; i++) {
	sm[i] = 0xff;
    }
    EVP_DigestUpdate(ctx, sm, 32);
    EVP_DigestUpdate(ctx, a, 32);
    EVP_DigestUpdate(ctx, M, len);
    EVP_DigestUpdate(ctx, Z, 64);
    EVP_DigestFinal_ex(ctx, r, NULL);
    sc_reduce(r);

    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(sm, &R);

    EVP_DigestInit_ex(ctx, NULL, NULL);
    EVP_DigestUpdate(ctx, sm, 32);
    EVP_DigestUpdate(ctx, A, 32);
    EVP_DigestUpdate(ctx, M, len);
    EVP_DigestFinal_ex(ctx, h, NULL);
    sc_reduce(h);

    sc_muladd(sm + 32, h, a, r);
    sm[63] &= 0x7f;
    sm[63] |= A[31] & 0x80;

    EVP_MD_CTX_free(ctx);
}

/*
 * signature = R || s
 *
 * A = convert_mont(u)
 * if not on_curve(A):
 *     return false
 * h = hash(R || A || M) (mod q)
 * Rcheck = sB - hA
 * return bytes_equal(R, Rcheck)
 */
static int xeddsa_verify(unsigned char *pk, unsigned char *sm, unsigned char *M,
			 int len)
{
    unsigned char a[32];
    unsigned char s[32];
    unsigned char h[64];
    unsigned char rcheck[32];
    ge_p3 A;
    ge_p2 R;
    EVP_MD_CTX *ctx;

    if (!convert_mont(a, pk)) {
	return 0;
    }
    memmove(s, sm + 32, 32);
    a[31] ^= s[31] & 0x80;
    s[31] &= 0x7f;
    if ((s[31] & 0xe0) != 0) {
	return 0;
    }
    if (ge_frombytes_negate_vartime(&A, a) != 0) {
	return 0;
    }

    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, sm, 32);
    EVP_DigestUpdate(ctx, a, 32);
    EVP_DigestUpdate(ctx, M, len);
    EVP_DigestFinal_ex(ctx, h, NULL);
    EVP_MD_CTX_free(ctx);
    sc_reduce(h);

    ge_double_scalarmult_vartime(&R, h, &A, s);
    ge_tobytes(rcheck, &R);

    return (crypto_verify_32(rcheck, sm) == 0);
}

/*
 * draft-irtf-cfrg-ristretto255-decaf448 section 4.2
 */
static int sqrt_ratio_m1(fe h, fe u, fe v)
{
    fe v3, check, r, a;
    int squared;

    /* r = (u * v^3) * (u * v^7)^((p-5)/8) */
    fe_sq(v3, v);
    fe_mul(v3, v3, v);			/* v3 = v^3 */
    fe_sq(r, v3);
    fe_mul(r, r, v);
    fe_mul(r, r, u);			/* r = uv^7 */

    fe_pow22523(r, r);			/* r = (uv^7)^((q-5)/8) */
    fe_mul(r, r, v3);
    fe_mul(r, r, u);			/* r = uv^3(uv^7)^((q-5)/8) */

    /* check = v * r^2 */
    fe_sq(check, r);
    fe_mul(check, check, v);

    squared = 1;
    fe_sub(a, check, u);
    if (fe_isnonzero(a)) {		/* check != u */
	fe_add(a, check, u);
	if (fe_isnonzero(a)) {		/* check != -u */
	    squared = 0;
	    fe_mul(a, u, sqrtm1);
	    fe_add(a, check, a);
	    if (!fe_isnonzero(a)) {	/* check == -u * SQRTM1 */
		fe_mul(r, r, sqrtm1);
	    }
	} else {			/* check == -u */
	    fe_mul(r, r, sqrtm1);
	}
    } else {				/* check == u */
	fe_mul(a, u, sqrtm1);
	fe_add(a, check, a);
	if (!fe_isnonzero(a)) {		/* check == -u * SQRTM1 */
	    fe_mul(r, r, sqrtm1);
	}
    }

    if (fe_isnegative(r)) {
	fe_neg(r, r);
    }

    fe_copy(h, r);
    return squared;
}

/*
 * draft-irtf-cfrg-ristretto255-decaf448 section 4.3.1
 */
static int decode(ge_p3 *h, const unsigned char *E)
{
    int i;
    fe s, a, one, u1, u2, v;

    if (E[31] > '\x7f') {
	return 0;			/* > p */
    } else if (E[31] == '\x7f') {
	for (i = 31; E[--i] == '\xff'; ) {
	    if (i == 1) {
		if (E[0] >= '\xed') {
		    return 0;		/* > p */
		}
		break;
	    }
	}
    }
    fe_frombytes(s, E);
    if (fe_isnegative(s)) {
	return 0;			/* non-canonical */
    }

    fe_sq(a, s);			/* ss = s^2 */
    fe_1(one);
    fe_sub(u1, one, a);			/* u1 = 1 - ss */
    fe_add(u2, one, a);			/* u2 = 1 + ss */
    fe_sq(a, u2);			/* u2_sqr = u2^2 */

    /* v = -(D * u1^2) - u2_sqr */
    fe_sq(v, u1);
    fe_mul(v, v, d);
    fe_neg(v, v);
    fe_sub(v, v, a);

    /* (was_square, invsqrt) = SQRT_RATIO_M1(1, v * u2_sqr) */
    fe_mul(a, v, a);
    if (!sqrt_ratio_m1(a, one, a)) {
	return 0;
    }

    fe_mul(h->X, a, u2);		/* den_x = invsqrt * u2 */
    fe_mul(h->Y, h->X, v);		/* den_y = invsqrt * den_x * v */
    fe_mul(h->Y, a, h->Y);

    /* x = CT_ABS(2 * s * den_x) */
    fe_mul(a, s, h->X);
    fe_add(h->X, a, a);
    if (fe_isnegative(h->X)) {
	fe_neg(h->X, h->X);
    }

    fe_mul(h->Y, u1, h->Y);		/* y = u1 * den_y */
    fe_1(h->Z);				/* z = 1 */
    fe_mul(h->T, h->X, h->Y);		/* t = x * y */

    return (!fe_isnegative(h->T));
}

static const fe invsqrta_d = {
    6111485, 4156064, -27798727, 12243468, -25904040,
    120897, 20826367, -7060776, 6093568, -1986012
};

/*
 * draft-irtf-cfrg-ristretto255-decaf448 section 4.3.2
 */
static void encode(unsigned char *s, const ge_p3 *h)
{
    fe a, u1, u2, one, z_inv, x, y;

    /* u1 = (z0 + y0) * (z0 - y0) */
    fe_add(u1, h->Z, h->Y);
    fe_sub(a, h->Z, h->Y);
    fe_mul(u1, u1, a);

    fe_mul(u2, h->X, h->Y);		/* u2 = x0 * y0 */

    /* (_, invsqrt) = SQRT_RATIO_M1(1, u1 * u2^2) */
    fe_sq(a, u2);
    fe_mul(a, u1, a);
    fe_1(one);
    sqrt_ratio_m1(a, one, a);

    fe_mul(u1, a, u1);			/* den1 = invsqrt * u1 */
    fe_mul(u2, a, u2);			/* den2 = invsqrt * u2 */

    /* z_inv = den1 * den2 * t0 */
    fe_mul(z_inv, u1, u2);
    fe_mul(z_inv, z_inv, h->T);

    /* rotate = IS_NEGATIVE(t0 * z_inv) */
    fe_mul(a, h->T, z_inv);
    if (fe_isnegative(a)) {
	fe_mul(x, h->Y, sqrtm1);	/* x = y0 * SQRT_M1 */
	fe_mul(y, h->X, sqrtm1);	/* y = x0 * SQRT_M1 */
	fe_mul(u2, u1, invsqrta_d);	/* den_inv = den1 * INVSQRT_A_MINUS_D */
    } else {
	fe_copy(x, h->X);		/* x = x0 */
	fe_copy(y, h->Y);		/* y = y0 */
					/* den_inv = den2 */
    }

    /* y = CT_SELECT(-y IF IS_NEGATIVE(x * z_inv) ELSE y) */
    fe_mul(a, x, z_inv);
    if (fe_isnegative(a)) {
	fe_neg(y, y);
    }

    /* s = CT_ABS(den_inv * (z - y)) */
    fe_sub(a, h->Z, y);
    fe_mul(a, u2, a);
    if (fe_isnegative(a)) {
	fe_neg(a, a);
    }
    fe_tobytes(s, a);
}

static const fe one_dsq = {
    6275446, -16617371, -22938544, -3773710, 11667077,
    7397348, -27922721, 1766195, -24433858, 672203
};
static const fe m1 = {
    -1, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const fe d_1sq = {
    15551795, -11097455, -13425098, -10125071, -11896535,
    10178284, -26634327, 4729244, -5282110, -10116402
};
static const fe sqrtad_1 = {
    24849947, -153582, -23613485, 6347715, -21072328,
    -667138, -25271143, -15367704, -870347, 14525639
};

/*
 * draft-irtf-cfrg-ristretto255-decaf448 section 4.3.4
 */
static void elligator_map(ge_p3 *h, unsigned char *s)
{
    fe t, r, one, u, v, a, c, N;
    ge_p1p1 R;

    fe_frombytes(t, s);

    /* r = SQRT_M1 * t^2 */
    fe_sq(r, t);
    fe_mul(r, sqrtm1, r);

    /* u = (r + 1) * ONE_MINUS_D_SQ */
    fe_1(one);
    fe_add(u, r, one);
    fe_mul(u, u, one_dsq);

    /* v = (-1 - r*D) * (r + D) */
    fe_mul(v, r, d);
    fe_sub(v, m1, v);
    fe_add(a, r, d);
    fe_mul(v, v, a);

    /* (was_square, s) = SQRT_RATIO_M1(u, v) */
    if (sqrt_ratio_m1(a, u, v)) {
	/* s = CT_SELECT(s IF was_square ELSE s_prime) */
	/* c = CT_SELECT(-1 IF was_square ELSE r) */
	fe_copy(c, m1);
    } else {
	/* s_prime = -CT_ABS(s*t) */
	fe_mul(a, a, t);
	if (!fe_isnegative(a)) {
	    fe_neg(a, a);
	}
	fe_copy(c, r);
    }

    /* N = c * (r - 1) * D_MINUS_ONE_SQ - v */
    fe_sub(N, r, one);
    fe_mul(N, N, c);
    fe_mul(N, N, d_1sq);
    fe_sub(N, N, v);

    fe_add(R.X, a, a);		/* w0 = 2 * s * v */
    fe_mul(R.X, R.X, v);
    fe_mul(R.Z, N, sqrtad_1);	/* w1 = N * SQRT_AD_MINUS_ONE */
    fe_sq(a, a);		/* w2 = 1 - s^2 */
    fe_sub(R.Y, one, a);
    fe_add(R.T, one, a);	/* w3 = 1 + s^2 */

    ge_p1p1_to_p3(h, &R);	/* (w0*w3, w2*w1, w1*w3, w0*w2) */
}

/*
 * multiply a point by a scalar
 */
static void mult(ge_p3 *h, const ge_p3 *A, const unsigned char *s)
{
    ge_cached C[16];
    ge_p3 B, D, E, F;
    ge_p1p1 R;
    ge_p2 S;
    int i;

    ge_p3_0(&B);				  ge_p3_to_cached(&C[0], &B);
						  ge_p3_to_cached(&C[1], A);
    ge_p3_dbl(&R, A);	   ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[2], &B);
    ge_add(&R, A, &C[2]);  ge_p1p1_to_p3(&D, &R); ge_p3_to_cached(&C[3], &D);
    ge_p3_dbl(&R, &B);	   ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[4], &B);
    ge_add(&R, A, &C[4]);  ge_p1p1_to_p3(&E, &R); ge_p3_to_cached(&C[5], &E);
    ge_p3_dbl(&R, &D);	   ge_p1p1_to_p3(&D, &R); ge_p3_to_cached(&C[6], &D);
    ge_add(&R, A, &C[6]);  ge_p1p1_to_p3(&F, &R); ge_p3_to_cached(&C[7], &F);
    ge_p3_dbl(&R, &B);	   ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[8], &B);
    ge_add(&R, A, &C[8]);  ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[9], &B);
    ge_p3_dbl(&R, &E);	   ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[10], &B);
    ge_add(&R, A, &C[10]); ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[11], &B);
    ge_p3_dbl(&R, &D);	   ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[12], &B);
    ge_add(&R, A, &C[12]); ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[13], &B);
    ge_p3_dbl(&R, &F);	   ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[14], &B);
    ge_add(&R, A, &C[14]); ge_p1p1_to_p3(&B, &R); ge_p3_to_cached(&C[15], &B);

    ge_p3_0(&B);
    for (i = 31; i > 0; --i) {
	ge_add(&R, &B, &C[s[i] >> 4]);	ge_p1p1_to_p2(&S, &R);
	ge_p2_dbl(&R, &S);		ge_p1p1_to_p2(&S, &R);
	ge_p2_dbl(&R, &S);		ge_p1p1_to_p2(&S, &R);
	ge_p2_dbl(&R, &S);		ge_p1p1_to_p2(&S, &R);
	ge_p2_dbl(&R, &S);		ge_p1p1_to_p3(&B, &R);

	ge_add(&R, &B, &C[s[i] & 0xf]);	ge_p1p1_to_p2(&S, &R);
	ge_p2_dbl(&R, &S);		ge_p1p1_to_p2(&S, &R);
	ge_p2_dbl(&R, &S);		ge_p1p1_to_p2(&S, &R);
	ge_p2_dbl(&R, &S);		ge_p1p1_to_p2(&S, &R);
	ge_p2_dbl(&R, &S);		ge_p1p1_to_p3(&B, &R);
    }

    ge_add(&R, &B, &C[s[0] >> 4]);	ge_p1p1_to_p2(&S, &R);
    ge_p2_dbl(&R, &S);			ge_p1p1_to_p2(&S, &R);
    ge_p2_dbl(&R, &S);			ge_p1p1_to_p2(&S, &R);
    ge_p2_dbl(&R, &S);			ge_p1p1_to_p2(&S, &R);
    ge_p2_dbl(&R, &S);			ge_p1p1_to_p3(&B, &R);

    ge_add(&R, &B, &C[s[0] & 0xf]);	ge_p1p1_to_p3(h, &R);
}


/*
 * compute Ed25519 signature with X25519 key
 */
static void xed25519_sign(LPC_frame f, int nargs, LPC_value retval)
{
    unsigned char rand[64];
    LPC_value val;
    LPC_string key, message, signature;

    if (nargs != 2) {
	lpc_runtime_error(f, "Wrong number of arguments for kfun encrypt");
    }
    val = lpc_frame_arg(f, nargs, 0);
    if (lpc_value_type(val) != LPC_TYPE_STRING) {
	lpc_runtime_error(f, "Bad argument 2 for kfun encrypt");
    }
    key = lpc_string_getval(val);
    if (lpc_string_length(key) != 32) {
	lpc_runtime_error(f, "Bad key");
    }
    val = lpc_frame_arg(f, nargs, 1);
    if (lpc_value_type(val) != LPC_TYPE_STRING) {
	lpc_runtime_error(f, "Bad argument 3 for kfun encrypt");
    }
    message = lpc_string_getval(val);

    signature = lpc_string_new(lpc_frame_dataspace(f), NULL, 64);
    RAND_bytes(rand, 64);
    xeddsa_sign(lpc_string_text(signature), lpc_string_text(message),
		lpc_string_length(message), lpc_string_text(key), rand);

    lpc_string_putval(retval, signature);
}

/*
 * verify Ed25519 signature with X25519 key
 */
static void xed25519_verify(LPC_frame f, int nargs, LPC_value retval)
{
    unsigned char rand[64];
    LPC_value val;
    LPC_string key, signature, message;

    if (nargs != 3) {
	lpc_runtime_error(f, "Wrong number of arguments for kfun decrypt");
    }
    val = lpc_frame_arg(f, nargs, 0);
    if (lpc_value_type(val) != LPC_TYPE_STRING) {
	lpc_runtime_error(f, "Bad argument 2 for kfun decrypt");
    }
    key = lpc_string_getval(val);
    if (lpc_string_length(key) != 32) {
	lpc_runtime_error(f, "Bad key");
    }
    val = lpc_frame_arg(f, nargs, 1);
    if (lpc_value_type(val) != LPC_TYPE_STRING) {
	lpc_runtime_error(f, "Bad argument 3 for kfun decrypt");
    }
    signature = lpc_string_getval(val);
    val = lpc_frame_arg(f, nargs, 2);
    if (lpc_value_type(val) != LPC_TYPE_STRING) {
	lpc_runtime_error(f, "Bad argument 4 for kfun decrypt");
    }
    message = lpc_string_getval(val);

    lpc_int_putval(retval,
		   xeddsa_verify(lpc_string_text(key),
				 lpc_string_text(signature),
				 lpc_string_text(message),
				 lpc_string_length(message)));
}

/*
 * string ristretto255_add(string r1, string r2)
 */
static void r255_add(LPC_frame f, int nargs, LPC_value retval)
{
    unsigned char buffer[32];
    LPC_value arg;
    LPC_string str;
    ge_p3 A, B;
    ge_cached C;
    ge_p1p1 R;

    arg = lpc_frame_arg(f, nargs, 0);
    str = lpc_string_getval(arg);
    if (lpc_string_length(str) != 32 || !decode(&A, lpc_string_text(str))) {
	lpc_runtime_error(f, "Bad argument 1 for kfun ristretto255_add");
    }
    arg = lpc_frame_arg(f, nargs, 1);
    str = lpc_string_getval(arg);
    if (lpc_string_length(str) != 32 || !decode(&B, lpc_string_text(str))) {
	lpc_runtime_error(f, "Bad argument 2 for kfun ristretto255_add");
    }

    ge_p3_to_cached(&C, &B);
    ge_add(&R, &A, &C);
    ge_p1p1_to_p3(&A, &R);
    encode(buffer, &A);

    lpc_string_putval(retval,
		      lpc_string_new(lpc_frame_dataspace(f), buffer, 32));
}

/*
 * string ristretto255_sub(string r1, string r2)
 */
static void r255_sub(LPC_frame f, int nargs, LPC_value retval)
{
    unsigned char buffer[32];
    LPC_value arg;
    LPC_string str;
    ge_p3 A, B;
    ge_cached C;
    ge_p1p1 R;

    arg = lpc_frame_arg(f, nargs, 0);
    str = lpc_string_getval(arg);
    if (lpc_string_length(str) != 32 || !decode(&A, lpc_string_text(str))) {
	lpc_runtime_error(f, "Bad argument 1 for kfun ristretto255_sub");
    }
    arg = lpc_frame_arg(f, nargs, 1);
    str = lpc_string_getval(arg);
    if (lpc_string_length(str) != 32 || !decode(&B, lpc_string_text(str))) {
	lpc_runtime_error(f, "Bad argument 2 for kfun ristretto255_sub");
    }

    ge_p3_to_cached(&C, &B);
    ge_sub(&R, &A, &C);
    ge_p1p1_to_p3(&A, &R);
    encode(buffer, &A);

    lpc_string_putval(retval,
		      lpc_string_new(lpc_frame_dataspace(f), buffer, 32));
}

/*
 * string ristretto255_neg(string r)
 */
static void r255_neg(LPC_frame f, int nargs, LPC_value retval)
{
    unsigned char buffer[32];
    LPC_value arg;
    LPC_string str;
    ge_p3 A;

    arg = lpc_frame_arg(f, nargs, 0);
    str = lpc_string_getval(arg);
    if (lpc_string_length(str) != 32 || !decode(&A, lpc_string_text(str))) {
	lpc_runtime_error(f, "Bad argument 1 for kfun ristretto255_neg");
    }

    fe_neg(A.X, A.X);
    fe_neg(A.T, A.T);
    encode(buffer, &A);

    lpc_string_putval(retval,
		      lpc_string_new(lpc_frame_dataspace(f), buffer, 32));
}

/*
 * string ristretto255_mult(string r, string s)
 */
static void r255_mult(LPC_frame f, int nargs, LPC_value retval)
{
    unsigned char buffer[32];
    LPC_value arg;
    LPC_string str;
    ge_p3 A;

    arg = lpc_frame_arg(f, nargs, 0);
    str = lpc_string_getval(arg);
    if (lpc_string_length(str) != 32 || !decode(&A, lpc_string_text(str))) {
	lpc_runtime_error(f, "Bad argument 1 for kfun ristretto255_mult");
    }
    arg = lpc_frame_arg(f, nargs, 1);
    str = lpc_string_getval(arg);
    if (lpc_string_length(str) != 32) {
	lpc_runtime_error(f, "Bad argument 2 for kfun ristretto255_mult");
    }

    mult(&A, &A, lpc_string_text(str));
    encode(buffer, &A);

    lpc_string_putval(retval,
		      lpc_string_new(lpc_frame_dataspace(f), buffer, 32));
}

/*
 * string ristretto255_map(string r)
 */
static void r255_map(LPC_frame f, int nargs, LPC_value retval)
{
    unsigned char buffer[32];
    LPC_value arg;
    LPC_string str;
    ge_p3 A;

    arg = lpc_frame_arg(f, nargs, 0);
    str = lpc_string_getval(arg);
    if (lpc_string_length(str) != 32) {
	lpc_runtime_error(f, "Bad argument 1 for kfun ristretto255_map");
    }

    elligator_map(&A, lpc_string_text(str));
    encode(buffer, &A);

    lpc_string_putval(retval,
		      lpc_string_new(lpc_frame_dataspace(f), buffer, 32));
}

static char xed25519_sign_proto[] = { LPC_TYPE_STRING, LPC_TYPE_STRING,
				      LPC_TYPE_STRING, 0 };
static char xed25519_verify_proto[] = { LPC_TYPE_INT, LPC_TYPE_STRING,
				        LPC_TYPE_STRING, LPC_TYPE_STRING, 0 };
static char r255_bin_proto[] = { LPC_TYPE_STRING, LPC_TYPE_STRING,
				 LPC_TYPE_STRING, 0 };
static char r255_mon_proto[] = { LPC_TYPE_STRING, LPC_TYPE_STRING, 0 };

static LPC_ext_kfun kf[] = {
    { "encrypt XEd25519 sign", xed25519_sign_proto, xed25519_sign },
    { "decrypt XEd25519 verify", xed25519_verify_proto, xed25519_verify },
    { "ristretto255_add", r255_bin_proto, r255_add },
    { "ristretto255_sub", r255_bin_proto, r255_sub },
    { "ristretto255_neg", r255_mon_proto, r255_neg },
    { "ristretto255_mult", r255_bin_proto, r255_mult },
    { "ristretto255_map", r255_mon_proto, r255_map }
};

int lpc_ext_init(int major, int minor, const char *config)
{
    lpc_ext_kfun(kf, sizeof(kf) / sizeof(LPC_ext_kfun));
    return 1;
}
