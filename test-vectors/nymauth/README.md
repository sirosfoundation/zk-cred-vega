# nym_auth test vectors

Files in this directory:

| File | What it is |
|---|---|
| `challenge-vectors.json` | Shared challenge vectors (SessionTranscript, e2), byte-identical in zk-cred-longfellow. `derive` and `rejects` are the Digital Credentials API handover (`OpenID4VPDCAPIHandover`), `digest` is e2 for a transcript already in hand. `derive_redirect` and `rejects_redirect` are the redirect / QR handover (`OpenID4VPHandover`, OpenID4VP 1.0 appendix B.2.6.1). |
| `redirect_vectors_gen.py` | Independent, stdlib-only generator of `derive_redirect` and `rejects_redirect` (own CBOR encoder). Anchored on the spec's non-normative example. `python3 -I redirect_vectors_gen.py` prints both arrays; they must equal the ones in `challenge-vectors.json`. |
| `nym-auth-mdoc.txt` | The reference nym_auth mdoc credential (base64url IssuerSigned). |
| `pseudonym.json` | The reference `secret_seed`, DST and the per-verifier pseudonyms, `verifier_input` and e2. |
| `verifier.json` | The verifier request of the reference proof: issuer key and, per format, T, E, C and the values above. |
| `reference-proof.bin` | A real Vega proof of the reference credential (96,079 bytes). |
| `shapes.zst` | The published R1CS shapes (step and core), one zstd frame. |

Notes on the redirect vectors:

* Over redirects the response is encrypted (`direct_post.jwt`), so the JWK thumbprint is always 32 bytes. A `null` thumbprint is a reject in `rejects_redirect` (with a `reason`); the DC API handover keeps `null` for an unencrypted response.
* `client_id` includes its Client Identifier Prefix; `response_uri` is the request's `response_uri`.
* Each `derive_redirect` entry gives `handover_info_hex` (the encoded `OpenID4VPHandoverInfo`), `session_transcript_hex` and `challenge_digest_hex`. The digest of the transcript alone is e2 for either handover.
* The new arrays are additive: a consumer that does not implement the redirect handover ignores them.
* There is no redirect `derive` entry point yet. `tests/nymauth_challenge_vectors.rs` and `go/nymauth` run the vectors through the channel-agnostic digest and check each reject breaks a stated rule.
