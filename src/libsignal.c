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
# include "ref10/fe_invert.c"
# include "ref10/fe_isnegative.c"
# include "ref10/fe_mul.c"
# include "ref10/fe_neg.c"
# include "ref10/fe_sq.c"
# include "ref10/fe_sq2.c"
# include "ref10/fe_sub.c"
# include "ref10/fe_tobytes.c"

# include "ref10/ge_madd.c"
# include "ref10/ge_p1p1_to_p2.c"
# include "ref10/ge_p1p1_to_p3.c"
# include "ref10/ge_p2_dbl.c"
# include "ref10/ge_p3_0.c"
# include "ref10/ge_p3_dbl.c"
# include "ref10/ge_p3_to_p2.c"
# include "ref10/ge_p3_tobytes.c"
# include "ref10/ge_precomp_0.c"
# define select ge_scalarmult_base_select
# include "ref10/ge_scalarmult_base.c"

# include "ref10/sc_muladd.c"
# define load_3 sc_reduce_load_3
# define load_4 sc_reduce_load_4
# include "ref10/sc_reduce.c"


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

static char xed25519_sign_proto[] = { LPC_TYPE_STRING, LPC_TYPE_STRING,
				      LPC_TYPE_STRING, 0 };

static LPC_ext_kfun kf[] = {
    { "encrypt XEd25519 sign", xed25519_sign_proto, xed25519_sign }
};

int lpc_ext_init(int major, int minor, const char *config)
{
    lpc_ext_kfun(kf, 1);
    return 1;
}
