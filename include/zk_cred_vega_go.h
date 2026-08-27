/*
 * zk_cred_vega_go.h — hand-written C header for zk-cred-vega's Go (cgo)
 * verifier ABI.
 *
 * This describes the plain `extern "C"` functions exported by
 * `src/go_ffi.rs`, built with the crate's *default* Cargo features (i.e.
 * WITHOUT `--features uniffi`).
 *
 * Do not confuse this with the UniFFI-generated header
 * (bindings/kotlin/... after `make bindings-kotlin`): that one describes a
 * completely different, RustBuffer-based ABI meant for UniFFI's own
 * Kotlin/Swift scaffolding, built WITH `--features uniffi`. UniFFI does not
 * target Go, and its RustBuffer wire protocol is not cgo-friendly, so this
 * crate exposes a second, separate, ordinary C ABI specifically for Go
 * instead - mirrors zk-cred-longfellow's own `zk_cred_longfellow_go.h` /
 * `src/go_ffi.rs` split exactly.
 *
 * Only the verify path is exposed here: a Go verifier never proves.
 *
 * A real shape difference from zk-cred-longfellow's C ABI: Longfellow's
 * `rust_verify_with_ppid` takes the *expected* attribute values as input
 * and returns only a status code. This crate's zk_cred_vega_verify() takes
 * only the proof and *returns* the recomputed public values via a
 * fixed-size out-param struct - the caller must independently check them
 * against whatever it already knows (issuer pubkey, wire-declared claim
 * values, current time). See src/go_ffi.rs's own module doc for why.
 *
 * This header is hand-maintained (not generated); keep it in sync with
 * `src/go_ffi.rs` by hand when that file's exported signatures change -
 * that file's own compile-time assertions will fail to build if
 * MAX_CLAIMS_V1/MAX_CLAIM_BYTES_V1/mso::TIMESTAMP_LEN ever change without
 * this header being updated to match.
 */

#ifndef ZK_CRED_VEGA_GO_H
#define ZK_CRED_VEGA_GO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque handle to a deserialized verifier key. Obtained from
 * zk_cred_vega_deserialize_verifier_key() and released with
 * zk_cred_vega_free_verifier_key(). Never dereference or introspect this
 * type from C/Go; treat it as an opaque pointer.
 */
typedef struct GoVegaVerifierKey GoVegaVerifierKey;

/* Circuit-fixed sizes (see src/go_ffi.rs's compile-time assertions). */
#define ZK_CRED_VEGA_MAX_CLAIMS      4   /* crate::MAX_CLAIMS_V1 */
#define ZK_CRED_VEGA_MAX_CLAIM_BYTES 176 /* crate::MAX_CLAIM_BYTES_V1 */
#define ZK_CRED_VEGA_TIMESTAMP_LEN   20  /* crate::mso::TIMESTAMP_LEN */

/*
 * One claim slot's verified disclosure outcome.
 *
 * `plaintext` is always ZK_CRED_VEGA_MAX_CLAIM_BYTES bytes; only the first
 * `real_len` are meaningful, and only when `disclosed != 0` (all-zero
 * otherwise).
 */
typedef struct {
    uint8_t disclosed;
    uint8_t digest[32];
    uint32_t real_len;
    uint8_t plaintext[ZK_CRED_VEGA_MAX_CLAIM_BYTES];
    uint32_t digest_id;
} CDisclosedClaim;

/*
 * The verified, bound public output of a presentation - a fixed-size (no
 * heap allocation) struct the caller allocates itself and passes a pointer
 * to zk_cred_vega_verify(). There is no corresponding free function since
 * nothing here is separately heap-allocated.
 *
 * `qx`/`qy`: the issuer's P-256 public key coordinates (for trust-anchor
 *   checking against the credential's own x5chain).
 * `claims`: each requested claim's disclosure outcome, in the same order
 *   the corresponding step circuits were given (match by `digest_id`, not
 *   array position, against whatever the caller requested).
 * `device_x`/`device_y`: the mdoc's device public key coordinates.
 * `signed_ts`/`valid_from_ts`/`valid_until_ts`: the MSO's own validity
 *   window, each exactly ZK_CRED_VEGA_TIMESTAMP_LEN ASCII bytes
 *   (e.g. "2026-08-20T00:00:00Z").
 */
/*
 * One claim slot's disclosed bytes, supplied IN to zk_cred_vega_verify().
 *
 * The IssuerSignedItem plaintext is no longer a public value of the proof:
 * it travels beside the proof and is bound by the blinded digest, which
 * verification checks. This mirrors BBS (disclosed_messages passed to
 * ProofVerify) and Longfellow (PublicAttribute fed into the statement).
 *
 * Set present = 0 for an undisclosed slot. Set present = 1 and fill
 * len/bytes for a disclosed one. Exactly MAX_CLAIMS (4) entries must be
 * passed, in claim-slot order.
 */
typedef struct {
    uint8_t present;
    size_t  len;
    uint8_t bytes[ZK_CRED_VEGA_MAX_CLAIM_BYTES];
} CDisclosedInput;

typedef struct {
    uint8_t qx[32];
    uint8_t qy[32];
    CDisclosedClaim claims[ZK_CRED_VEGA_MAX_CLAIMS];
    uint8_t device_x[32];
    uint8_t device_y[32];
    uint8_t signed_ts[ZK_CRED_VEGA_TIMESTAMP_LEN];
    uint8_t valid_from_ts[ZK_CRED_VEGA_TIMESTAMP_LEN];
    uint8_t valid_until_ts[ZK_CRED_VEGA_TIMESTAMP_LEN];
} CVerifyResult;

/*
 * Deserializes a published verifier-key artifact (fetched from
 * go-zk-circuits) into an opaque handle usable by zk_cred_vega_verify(),
 * or NULL on failure.
 *
 * `bytes`/`len`: the verifier-key artifact bytes (decompressed).
 * `error_out`: optional (may be NULL). On failure, if non-NULL,
 * `*error_out` is set to a newly allocated, NUL-terminated, UTF-8 error
 * string that the caller must eventually pass to
 * zk_cred_vega_free_error_string(). On success, `*error_out` is set to
 * NULL.
 *
 * Deserializing a verifier key is comparatively cheap (no circuit
 * compilation happens here), but a long-lived Go process should still
 * cache the returned handle across many zk_cred_vega_verify() calls rather
 * than deserializing on every verification.
 */
GoVegaVerifierKey *zk_cred_vega_deserialize_verifier_key(
    const uint8_t *bytes,
    size_t len,
    char **error_out
);

/*
 * Frees a verifier-key handle previously returned by
 * zk_cred_vega_deserialize_verifier_key().
 *
 * Passing NULL is a no-op. Passing the same non-NULL pointer more than
 * once, or using the pointer after freeing it, is undefined behavior (the
 * same rules as free() in C). The caller must also ensure no
 * zk_cred_vega_verify() call using this handle is still in flight on
 * another thread when this is called.
 */
void zk_cred_vega_free_verifier_key(GoVegaVerifierKey *verifier_key);

/*
 * Frees an error string previously written into an `error_out`
 * out-parameter by a function in this header. Passing NULL is a no-op.
 */
void zk_cred_vega_free_error_string(char *ptr);

/*
 * Verifies a proof and checks the step<->core binding in one call - a
 * caller never sees an unbound "valid" proof. This performs the same real
 * cryptographic verification as the crate's safe Rust API; it is a thin
 * parsing/validation wrapper around it, not a separate, weaker check.
 *
 * `verifier_key`: a live handle from zk_cred_vega_deserialize_verifier_key()
 *   (must not be NULL, freed, or concurrently being freed by another
 *   thread).
 * `proof`/`proof_len`: the serialized proof bytes.
 * `disclosed`/`disclosed_len`: REQUIRED. Exactly MAX_CLAIMS (4) entries in
 *   claim-slot order, carrying the real IssuerSignedItem bytes for every
 *   slot the proof reports as disclosed and present = 0 for the rest.
 *   These bytes are not inside the proof; verification binds them by
 *   re-deriving their blinded digest. A mismatch fails verification.
 * `result_out`: optional (may be NULL, in which case the proof is still
 *   validated and a status code returned, just without writing the public
 *   values anywhere). If non-NULL, must point to a valid, writable
 *   CVerifyResult - filled in on success.
 * `error_out`: optional (may be NULL); see
 *   zk_cred_vega_deserialize_verifier_key() for the out-parameter contract.
 *
 * Returns 0 on success. On failure, returns a negative status code
 * (-1: input validation or verification error; -2: an internal panic was
 * caught) and, if `error_out` is non-NULL, writes an owned error message
 * there.
 *
 * IMPORTANT (see this header's own top-of-file note): unlike Longfellow's
 * rust_verify_with_ppid, a `0` return here only means "this is a
 * structurally valid, internally-consistent proof" - it does NOT mean the
 * disclosed values match what the caller expects. The caller MUST
 * additionally check `result_out`'s qx/qy against the trust-evaluated
 * issuer certificate, each disclosed claim's plaintext against the
 * wire-declared value, and the validity timestamps against the current
 * time, before treating the presentation as accepted.
 */
int32_t zk_cred_vega_verify(
    const GoVegaVerifierKey *verifier_key,
    const uint8_t *proof,
    size_t proof_len,
    const CDisclosedInput *disclosed,
    size_t disclosed_len,
    CVerifyResult *result_out,
    char **error_out
);

#ifdef __cplusplus
}
#endif

#endif /* ZK_CRED_VEGA_GO_H */
