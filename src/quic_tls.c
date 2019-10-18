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
int quic_hkdf_extract(const EVP_MD *md,
                      unsigned char *buf, size_t *buflen,
                      unsigned char *key, size_t keylen,
                      unsigned char *salt, size_t saltlen)
{
	return HKDF_extract(buf, buflen, md, key, keylen, salt, saltlen);
}

int quic_hkdf_expand(const EVP_MD *md,
                     unsigned char *buf, size_t buflen,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *label, size_t labellen)
{
	return HKDF_expand(buf, buflen, md, key, keylen, label, labellen);
}
#else
int quic_hkdf_extract(const EVP_MD *md,
                      unsigned char *buf, size_t *buflen,
                      unsigned char *key, size_t keylen,
                      unsigned char *salt, size_t saltlen)
{
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx)
        return 0;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0 ||
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

int quic_hkdf_expand(const EVP_MD *md,
                     unsigned char *buf, size_t buflen,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *label, size_t labellen)
{
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx)
        return 0;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0 ||
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
int quic_hkdf_expand_label(const EVP_MD *md,
                           unsigned char *buf, size_t buflen,
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

	return quic_hkdf_expand(md, buf, buflen,
	                        key, keylen, hdkf_label, pos - hdkf_label);
}

/*
 * This function derives two keys from <secret> is <ctx> as TLS cryptographic context.
 * ->key is the TLS key to be derived to encrypt/decrypt data at TLS level.
 * ->iv is the initialization vector to be used with ->key.
 * ->hp_key is the key to be derived for header protection.
 * Obviouly these keys have the same size becaused derived with the same TLS cryptographic context.
 */
ssize_t quic_tls_derive_packet_protection_keys(const EVP_CIPHER *aead, const EVP_MD *md,
                                               unsigned char *key, size_t keylen,
                                               unsigned char *iv, size_t ivlen,
                                               unsigned char *hp_key, size_t hp_keylen,
                                               const unsigned char *secret, size_t secretlen)
{
	size_t aead_keylen = (size_t)EVP_CIPHER_key_length(aead);
	size_t aead_ivlen = (size_t)EVP_CIPHER_iv_length(aead);
	const unsigned char    key_label[] = "quic key";
	const unsigned char     iv_label[] = "quic iv";
	const unsigned char hp_key_label[] = "quic hp";

	fprintf(stderr, "%s AEAD key len: %zu\n", __func__, aead_keylen);
	fprintf(stderr, "%s AEAD IV len: %zu\n", __func__, aead_ivlen);
	if (aead_keylen > keylen || aead_ivlen > ivlen)
		return 0;

	if (!quic_hkdf_expand_label(md, key, aead_keylen, secret, secretlen,
	                            key_label, sizeof key_label - 1) ||
	    !quic_hkdf_expand_label(md, iv, aead_ivlen, secret, secretlen,
	                            iv_label, sizeof iv_label - 1) ||
	    !quic_hkdf_expand_label(md, hp_key, hp_keylen, secret, secretlen,
	                            hp_key_label, sizeof hp_key_label - 1))
		return 0;

	hexdump(key, keylen, "===> %s: key:\n", __func__);
	hexdump(iv, ivlen, "===> %s: iv:\n", __func__);
	hexdump(hp_key, hp_keylen, "===> %s: hp_key:\n", __func__);

	return 1;
}

/*
 * Derive the initial secret from <secret> and QUIC version dependent salt.
 * Returns the size of the derived secret if succeeded, 0 if not.
 */
int quic_derive_initial_secret(const EVP_MD *md,
                               unsigned char *initial_secret, size_t initial_secret_sz,
                               unsigned char *secret, size_t secret_sz)
{
	if (!quic_hkdf_extract(md, initial_secret, &initial_secret_sz, secret, secret_sz,
	                       initial_salt, sizeof initial_salt))
		return 0;

	return 1;
}

/*
 * Derive the client initial secret from the initial secret.
 * Returns the size of the derived secret if succeeded, 0 if not.
 */
ssize_t quic_tls_derive_initial_secrets(const EVP_MD *md,
                                        unsigned char *rx, size_t rx_sz,
                                        unsigned char *tx, size_t tx_sz,
                                        const unsigned char *secret, size_t secret_sz,
                                        int server)
{
	const unsigned char client_label[] = "client in";
	const unsigned char server_label[] = "server in";
	unsigned char *rxp, *txp;
	size_t rxp_sz, txp_sz;

	if (server) {
		rxp = rx; rxp_sz = rx_sz;
		txp = tx; txp_sz = tx_sz;
	}
	else {
		rxp = tx; rxp_sz = tx_sz;
		txp = rx; txp_sz = rx_sz;
	}

	if (!quic_hkdf_expand_label(md, rxp, rxp_sz, secret, secret_sz,
	                            client_label, sizeof client_label - 1) ||
	    !quic_hkdf_expand_label(md, txp, txp_sz, secret, secret_sz,
	                            server_label, sizeof server_label - 1))
	    return 0;

	hexdump(rxp, rxp_sz, "CLIENT INITIAL SECRET:\n");
	hexdump(txp, txp_sz, "SERVER INITIAL SECRET:\n");

	return 1;
}
