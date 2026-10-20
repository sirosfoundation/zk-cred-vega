#!/usr/bin/env python3
"""Independent generator for the derive_redirect and rejects_redirect sections of challenge-vectors.json (OpenID4VPHandover, OpenID4VP 1.0 B.2.6.1).
stdlib only; its own minimal CBOR encoder (definite lengths, shortest heads)."""
import hashlib, json, base64, sys

def head(major, n):
    m = major << 5
    if n < 24: return bytes([m | n])
    if n < 256: return bytes([m | 24, n])
    if n < 65536: return bytes([m | 25]) + n.to_bytes(2, 'big')
    if n < 2**32: return bytes([m | 26]) + n.to_bytes(4, 'big')
    return bytes([m | 27]) + n.to_bytes(8, 'big')
def tstr(s): b = s.encode('utf-8'); return head(3, len(b)) + b
def bstr(b): return head(2, len(b)) + b
NULL = b'\xf6'
def arr(*items): return head(4, len(items)) + b''.join(items)
def sha(b): return hashlib.sha256(b).digest()

def handover_info(client_id, nonce, thumb, response_uri):
    return arr(tstr(client_id), tstr(nonce), NULL if thumb is None else bstr(thumb), tstr(response_uri))
def transcript(client_id, nonce, thumb, response_uri):
    h = arr(tstr("OpenID4VPHandover"), bstr(sha(handover_info(client_id, nonce, thumb, response_uri))))
    return arr(NULL, NULL, h)
def dcapi_transcript(origin, nonce, thumb):
    info = arr(tstr(origin), tstr(nonce), NULL if thumb is None else bstr(thumb))
    return arr(NULL, NULL, arr(tstr("OpenID4VPDCAPIHandover"), bstr(sha(info))))
def tag24(enc): return head(6, 24) + bstr(enc)
def e2(st, doc_type):
    da = arr(tstr("DeviceAuthentication"), st, tstr(doc_type), tag24(b'\xa0'))
    sig = arr(tstr("Signature1"), bstr(bytes([0xa1, 0x01, 0x26])), bstr(b''), bstr(tag24(da)))
    return sha(sig)
def rfc7638(jwk):  # EC: members crv,kty,x,y in lexicographic order, no whitespace
    s = '{"crv":"%s","kty":"%s","x":"%s","y":"%s"}' % (jwk['crv'], jwk['kty'], jwk['x'], jwk['y'])
    return sha(s.encode())

DOC = "eu.europa.ec.eudi.nym_auth.1"

# --- anchor: the spec's own non-normative example (OpenID4VP 1.0 B.2.6.1) ---
spec_jwk = {"kty":"EC","crv":"P-256","x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0","y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc"}
spec_thumb = rfc7638(spec_jwk)
assert spec_thumb.hex() == "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047", spec_thumb.hex()
spec_info = ("847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767426b786a7831726463397564527276654b7653734a4971383061766c58654c4868477771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365")
ci, n, ru = "x509_san_dns:example.com", "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA", "https://example.com/response"
assert handover_info(ci, n, spec_thumb, ru).hex() == spec_info
spec_st = "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
assert transcript(ci, n, spec_thumb, ru).hex() == spec_st
assert sha(bytes.fromhex(spec_info)).hex() == "048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"

T11 = bytes([0x11]) * 32
cases = [
 ("OpenID4VP 1.0 B.2.6.1 non-normative example (client_id with x509_san_dns prefix, thumbprint of the example JWK)", ci, n, spec_thumb, ru),
 ("nym_auth, verifier 1: x509_san_dns client_id, encrypted response (direct_post.jwt), thumbprint 0x11*32", "x509_san_dns:verifier.example", "pOA0oqEAhLnqug2r7Ve4tQ", T11, "https://verifier.example/verification/direct_post"),
 ("nym_auth, verifier 1: same request, unencrypted response (jwk thumbprint null)", "x509_san_dns:verifier.example", "pOA0oqEAhLnqug2r7Ve4tQ", None, "https://verifier.example/verification/direct_post"),
 ("nym_auth, verifier 2: other client_id and nonce", "x509_san_dns:other-verifier.example", "6YfsJcysIReLorHGvKlsFQ", T11, "https://other-verifier.example/cb"),
 ("client_id with another prefix (x509_hash) and a hash-shaped identifier", "x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk", "0123456789abcdefghijkl", T11, "https://verifier.example/response"),
 ("client_id without a Client Identifier Prefix (pre-registered), response_uri with a query", "verifier.example", "0123456789abcdefghijkl", None, "https://verifier.example/response?session=1"),
 ("non-ASCII response_uri (a CBOR text length is the UTF-8 byte length) and a response_uri over 255 bytes (two-byte CBOR length head)", "x509_san_dns:xn--bcher-kva.example", "0123456789abcdefghijkl", T11, "https://bücher.example/" + "p"*260),
]
out = []
for name, ci_, n_, th, ru_ in cases:
    st = transcript(ci_, n_, th, ru_)
    out.append({
        "name": name, "client_id": ci_, "nonce": n_, "response_uri": ru_, "doc_type": DOC,
        "jwk_thumbprint_hex": None if th is None else th.hex(),
        "handover_info_hex": handover_info(ci_, n_, th, ru_).hex(),
        "session_transcript_hex": st.hex(), "challenge_digest_hex": e2(st, DOC).hex(),
    })
# cross-channel: the same nonce/thumbprint on the DC API never gives the redirect transcript
d = dcapi_transcript("https://verifier.example", "pOA0oqEAhLnqug2r7Ve4tQ", T11)
assert d.hex() != out[1]["session_transcript_hex"]
# regression anchor: the existing DC API vector 3 of the shared file
assert dcapi_transcript("https://verifier.example", "pOA0oqEAhLnqug2r7Ve4tQ", T11).hex() == "83f6f682764f70656e4944345650444341504948616e646f766572582098a74db4c57a62c35763573aa80ce0583c9556e27bddca7c7172eaf38285fd4c"

rej = []
base = dict(client_id="x509_san_dns:verifier.example", nonce="pOA0oqEAhLnqug2r7Ve4tQ", response_uri="https://verifier.example/verification/direct_post", doc_type=DOC, jwk_thumbprint_hex=None)
def r(name, **kw):
    d = dict(base); d.update(kw); rej.append({"name": name, "op": "derive_redirect", **d})
r("empty client_id", client_id="")
r("empty nonce", nonce="")
r("15-character nonce", nonce="abcdefghijklmno")
r("empty response_uri", response_uri="")
r("empty docType", doc_type="")
r("31-byte JWK thumbprint", jwk_thumbprint_hex="11"*31)
r("33-byte JWK thumbprint", jwk_thumbprint_hex="11"*33)
json.dump({"derive_redirect": out, "rejects_redirect": rej}, sys.stdout, indent=1, ensure_ascii=False)
