#include <string.h>

#include <openssl/ssl.h>

#if defined(OPENSSL_IS_BORINGSSL)
#include <openssl/hkdf.h>
#else
#include <openssl/evp.h>
#include <openssl/kdf.h>
#endif

#include <types/quic_tls.h>

__attribute__((format (printf, 3, 4)))
void hexdump(const void *buf, size_t buflen, const char *title_fmt, ...);

/* Initial salt depending on QUIC version to derive client/server initial secrets.
 * This one is for draft-23 QUIC version.
 */
unsigned char initial_salt[20] = {
	0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a,
	0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
	0xbe, 0xf9, 0xf5, 0x02,
};

#if defined(OPENSSL_IS_BORINGSSL)
int quic_hdkf_extract(unsigned char *buf, size_t *buflen, const EVP_MD *md,
                      unsigned char *key, size_t keylen,
                      unsigned char *salt, size_t saltlen)
{
	return HKDF_extract(buf, buflen, EVP_sha256(), key, keylen, salt, saltlen);
}

int quic_hdkf_expand(unsigned char *buf, size_t buflen, const EVP_MD *md,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *label, size_t labellen)
{
	return HKDF_expand(buf, buflen, EVP_sha256(), key, keylen, label, labellen);
}
#else
int quic_hdkf_extract(unsigned char *buf, size_t *buflen, const EVP_MD *md,
                      unsigned char *key, size_t keylen,
                      unsigned char *salt, size_t saltlen)
{
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx)
        return 0;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, saltlen) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, key, keylen) <= 0 ||
        EVP_PKEY_derive(ctx, buf, buflen) <= 0)
        goto err;

    EVP_PKEY_CTX_free(ctx);
    return 1;

 err:
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int quic_hdkf_expand(unsigned char *buf, size_t buflen, const EVP_MD *md,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *label, size_t labellen)
{
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx)
        return 0;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, key, keylen) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, label, labellen) <= 0 ||
        EVP_PKEY_derive(ctx, buf, &buflen) <= 0)
        goto err;

    EVP_PKEY_CTX_free(ctx);
    return 1;

 err:
    EVP_PKEY_CTX_free(ctx);
    return 0;
}
#endif

/* https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#protection-keys
 * refers to:
 *
 * https://tools.ietf.org/html/rfc8446#section-7.1:
 * 7.1.  Key Schedule
 *
 * The key derivation process makes use of the HKDF-Extract and
 * HKDF-Expand functions as defined for HKDF [RFC5869], as well as the
 * functions defined below:
 *
 *     HKDF-Expand-Label(Secret, Label, Context, Length) =
 *          HKDF-Expand(Secret, HkdfLabel, Length)
 *
 *     Where HkdfLabel is specified as:
 *
 *     struct {
 *         uint16 length = Length;
 *         opaque label<7..255> = "tls13 " + Label;
 *         opaque context<0..255> = Context;
 *     } HkdfLabel;
 *
 *     Derive-Secret(Secret, Label, Messages) =
 *          HKDF-Expand-Label(Secret, Label,
 *                            Transcript-Hash(Messages), Hash.length)
 *
 */
int quic_hdkf_expand_label(unsigned char *buf, size_t buflen, const EVP_MD *md,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *label, size_t labellen)
{
	unsigned char hdkf_label[256], *pos;
	const unsigned char hdkf_label_label[] = "tls13 ";
	size_t hdkf_label_label_sz = sizeof hdkf_label_label - 1;

	pos = hdkf_label;
	*pos++ = buflen >> 8;
	*pos++ = buflen & 0xff;
	*pos++ = hdkf_label_label_sz + labellen;
	memcpy(pos, hdkf_label_label, hdkf_label_label_sz);
	pos += hdkf_label_label_sz;
	memcpy(pos, label, labellen);
	pos += labellen;
	*pos++ = '\0';

	return quic_hdkf_expand(buf, buflen, md,
	                        key, keylen, hdkf_label, pos - hdkf_label);
}

ssize_t quic_derive_packet_protection_key(struct quic_tls_ctx *ctx,
                                          const unsigned char *secret, size_t secretlen)
{
	size_t keylen = EVP_CIPHER_key_length(ctx->aead);
	size_t ivlen = EVP_CIPHER_iv_length(ctx->aead);
	const unsigned char key_label[] = "quic key";
	const unsigned char iv_label[] = "quic iv";
	const unsigned char hp_key_label[] = "quic hp";

	if (!quic_hdkf_expand_label(ctx->key, keylen, ctx->md, secret, secretlen,
	                            key_label, sizeof key_label - 1) ||
	    !quic_hdkf_expand_label(ctx->iv, ivlen, ctx->md, secret, secretlen,
	                            iv_label, sizeof iv_label - 1) ||
	    !quic_hdkf_expand_label(ctx->hp_key, keylen, ctx->md, secret, secretlen,
	                            hp_key_label, sizeof hp_key_label - 1))
		return 0;

	hexdump(ctx->key, keylen, "===> %s: key:\n", __func__);
	hexdump(ctx->iv, ivlen, "===> %s: iv:\n", __func__);
	hexdump(ctx->hp_key, keylen, "===> %s: hp_key:\n", __func__);
	return keylen;
}

/*
 * Derive the initial secret from the CID and QUIC version dependent salt.
 * Returns the size of the derived secret if succeeded, 0 if not.
 */
static int quic_derive_initial_secret(struct quic_tls_ctx *ctx, unsigned char *cid, size_t cid_len)
{
	size_t outlen;

	outlen = sizeof ctx->initial_secret;
	if (!quic_hdkf_extract(ctx->initial_secret, &outlen, ctx->md,
	                       cid, cid_len,
	                       initial_salt, sizeof initial_salt))
		return 0;

	return outlen;
}

/*
 * Derive the client initial secret from the initial secret.
 * Returns the size of the derived secret if succeeded, 0 if not.
 */
static ssize_t quic_derive_client_initial_secret(struct quic_tls_ctx *ctx)
{
	size_t outlen;
	const unsigned char label[] = "client in";

	outlen = sizeof ctx->rx_initial_secret;
	if (!quic_hdkf_expand_label(ctx->rx_initial_secret, outlen, ctx->md,
	                            ctx->initial_secret, sizeof ctx->initial_secret,
	                            label, sizeof label - 1))
	    return 0;

	hexdump(ctx->rx_initial_secret, outlen, "CLIENT INITIAL SECRET:\n");
	return outlen;
}

/*
 * Derive the client secret key from the the client initial secret.
 * Returns the size of the derived key if succeeded, 0 if not.
 */
static ssize_t quic_derive_key(struct quic_tls_ctx *ctx)
{
	size_t outlen;
	const unsigned char label[] = "quic key";

	outlen = sizeof ctx->key;
	if (!quic_hdkf_expand_label(ctx->key, outlen, ctx->md,
	                            ctx->rx_initial_secret, sizeof ctx->rx_initial_secret,
	                            label, sizeof label - 1))
	    return 0;

	hexdump(ctx->key, outlen, "KEY:\n");
	return outlen;
}

/*
 * Derive the client IV from the client initial secret.
 * Returns the size of this IV if succeeded, 0 if not.
 */
static ssize_t quic_derive_iv(struct quic_tls_ctx *ctx)
{
	size_t outlen;
	const unsigned char label[] = "quic iv";

	outlen = sizeof ctx->iv;
	if (!quic_hdkf_expand_label(ctx->iv, outlen, ctx->md,
	                            ctx->rx_initial_secret, sizeof ctx->rx_initial_secret,
	                            label, sizeof label - 1))
	    return 0;

	hexdump(ctx->iv, outlen, "IV:\n");
	return outlen;
}

/*
 * Derive the client header protection key from the client initial secret.
 * Returns the size of this key if succeeded, 0, if not.
 */
static ssize_t quic_derive_hp(struct quic_tls_ctx *ctx)
{
	size_t outlen;
	const unsigned char label[] = "quic hp";

	outlen = sizeof ctx->hp_key;
	if (!quic_hdkf_expand_label(ctx->hp_key, outlen, ctx->md,
	                            ctx->rx_initial_secret, sizeof ctx->rx_initial_secret,
	                            label, sizeof label - 1))
	    return 0;

	hexdump(ctx->hp_key, outlen, "HP:\n");
	return outlen;
}

/*
 * Initialize the client crytographic secrets for a new connection.
 * Must be called after having received a new QUIC client Initial packet.
 * Return 1 if succeeded, 0 if not.
 */
int quic_client_setup_crypto_ctx(struct quic_tls_ctx *ctx, unsigned char *cid, size_t cid_len)
{
	if (!quic_derive_initial_secret(ctx, cid, cid_len) ||
	    !quic_derive_client_initial_secret(ctx) ||
	    !quic_derive_key(ctx) ||
	    !quic_derive_iv(ctx) ||
	    !quic_derive_hp(ctx))
		return 0;

	return 1;
}

