/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * zk_cred_vega_nymauth_go.h - hand-written C header for the nymauth (age range and pseudonym)
 * verifier and prover ABI of zk-cred-vega, for a Go (cgo) caller.
 *
 * It describes the plain `extern "C"` functions of `src/nymauth_go_ffi.rs`, built with the crate's
 * default Cargo features (no `--features uniffi`). Like `zk_cred_vega_go.h` it is maintained by
 * hand: keep it in step with that file.
 *
 * Contract (see the module docs of `src/nymauth_vega.rs`): the statement's time, challenge digest
 * and verifier_input must be the verifier's own, never taken from the holder or the presentation;
 * derive the challenge digest with zk_cred_vega_nymauth_derive_challenge().
 *
 * Every function returns a status code and never aborts; a panic inside is returned as
 * ZK_NYM_INTERNAL. Nothing is dereferenced when a pointer is null or a length is past its cap
 * (ZK_NYM_INVALID_ARG).
 */

#ifndef ZK_CRED_VEGA_NYMAUTH_GO_H
#define ZK_CRED_VEGA_NYMAUTH_GO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. */
#define ZK_NYM_OK                        0
#define ZK_NYM_INVALID_ARG               1  /* null pointer, or a length past its cap */
#define ZK_NYM_INVALID_INPUT             2  /* malformed value, range, issuer key */
#define ZK_NYM_INVALID_SHAPES            3
#define ZK_NYM_UNKNOWN_CIRCUIT           4  /* shapes are not an approved circuit */
#define ZK_NYM_PROVER_FAILED             6
#define ZK_NYM_PROOF_INVALID             7  /* the proof does not verify, or a step instance's position differs */
#define ZK_NYM_MISMATCH                  8  /* proof verifies, but not for the named values */
#define ZK_NYM_INTERNAL                  9  /* a panic was caught */
#define ZK_NYM_PROOF_ENCODING            10 /* past the cap, not decodable, or bytes after its end */
#define ZK_NYM_REFUSED_SEED_MISMATCH     20 /* prove: secret_seed does not open the credential's ssc */
#define ZK_NYM_REFUSED_ISSUER_SIGNATURE  21
#define ZK_NYM_REFUSED_DEVICE_SIGNATURE  22
#define ZK_NYM_REFUSED_CREDENTIAL        23

/* Opaque handle to the keys of the approved circuit. */
typedef struct ZkNymKeys ZkNymKeys;

/* A byte or text argument (text is UTF-8, no terminator). */
typedef struct {
    const uint8_t *ptr;
    size_t len;
} ZkNymSlice;

/* The values the verifier names. */
typedef struct {
    ZkNymSlice issuer_key_x;     /* 32 bytes, big-endian */
    ZkNymSlice issuer_key_y;     /* 32 bytes, big-endian */
    ZkNymSlice time;             /* YYYY-MM-DDThh:mm:ssZ */
    ZkNymSlice earliest;         /* YYYY-MM-DD, 0000-00-00 for no lower bound */
    ZkNymSlice cutoff;           /* YYYY-MM-DD, 9999-12-31 for no upper bound */
    ZkNymSlice challenge_digest; /* e2, 32 bytes */
    ZkNymSlice verifier_input;   /* SHA-256(verifier_id), 32 bytes */
} ZkNymStatement;

/* What only the holder has. secret_seed (16 bytes) is zeroed in place by prove. */
typedef struct {
    ZkNymSlice issuer_signed;     /* IssuerSigned as CBOR */
    uint8_t *secret_seed;
    size_t secret_seed_len;
    ZkNymSlice device_signature;  /* r || s, 64 bytes */
} ZkNymHolder;

/* Builds the keys from the decompressed shapes. *keys_out is null on failure. */
int32_t zk_cred_vega_nymauth_load_keys(const uint8_t *shapes, size_t shapes_len, ZkNymKeys **keys_out);

/* Releases the handle. Null is ignored. Do not free twice. */
void zk_cred_vega_nymauth_free_keys(ZkNymKeys *keys);

/* Releases a buffer returned by prove or derive_challenge (same pointer and length). */
void zk_cred_vega_nymauth_free_buffer(uint8_t *ptr, size_t len);

/* ZK_NYM_OK only when the proof is accepted; writes the 32-byte pseudonym to pseudonym_out. */
int32_t zk_cred_vega_nymauth_verify(const ZkNymKeys *keys, const ZkNymStatement *statement,
                                    const uint8_t *proof, size_t proof_len, uint8_t *pseudonym_out);

/* Proves. On success *proof_out/*proof_len_out is the proof (free_buffer) and pseudonym_out (32
 * bytes) the pseudonym. holder->secret_seed is zeroed on every path. */
int32_t zk_cred_vega_nymauth_prove(const ZkNymKeys *keys, const ZkNymStatement *statement,
                                   const ZkNymHolder *holder, uint8_t **proof_out,
                                   size_t *proof_len_out, uint8_t *pseudonym_out);

/* Derives e2 (32 bytes to e2_out) and the transcript seed (the SessionTranscript, free_buffer)
 * per the circuits' SPEC.md section 3. jwk_thumbprint: {NULL, 0} for none, or 32 bytes. */
int32_t zk_cred_vega_nymauth_derive_challenge(ZkNymSlice origin, ZkNymSlice nonce,
                                              ZkNymSlice doc_type, ZkNymSlice jwk_thumbprint,
                                              uint8_t **transcript_out,
                                              size_t *transcript_len_out, uint8_t *e2_out);

/* e2 (32 bytes to e2_out) for a SessionTranscript in hand and the credential's docType. */
int32_t zk_cred_vega_nymauth_challenge_digest(ZkNymSlice session_transcript, ZkNymSlice doc_type,
                                              uint8_t *e2_out);

/* SHA-256(client_id) (32 bytes to out): the statement's verifier_input. */
int32_t zk_cred_vega_nymauth_verifier_input(ZkNymSlice client_id, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ZK_CRED_VEGA_NYMAUTH_GO_H */
