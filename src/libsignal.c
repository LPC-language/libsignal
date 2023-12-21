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

static char xed25519_sign_proto[] = { LPC_TYPE_STRING, LPC_TYPE_STRING,
				      LPC_TYPE_STRING, 0 };
static char xed25519_verify_proto[] = { LPC_TYPE_INT, LPC_TYPE_STRING,
				        LPC_TYPE_STRING, LPC_TYPE_STRING, 0 };

static LPC_ext_kfun kf[] = {
    { "encrypt XEd25519 sign", xed25519_sign_proto, xed25519_sign },
    { "decrypt XEd25519 verify", xed25519_verify_proto, xed25519_verify }
};

int lpc_ext_init(int major, int minor, const char *config)
{
    lpc_ext_kfun(kf, 2);
    return 1;
}
