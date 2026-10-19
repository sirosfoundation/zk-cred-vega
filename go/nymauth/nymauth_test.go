// SPDX-License-Identifier: BSD-2-Clause

package nymauth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var vectors = filepath.Join("..", "..", "test-vectors", "nymauth")

func read(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectors, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var (
	once   sync.Once
	shapes []byte
	keys   *Keys
	loadEr error
)

// loaded decompresses the published shapes (the zstd command line tool; Go has no zstd in its
// standard library) and builds the keys once.
func loaded(t testing.TB) *Keys {
	t.Helper()
	once.Do(func() {
		out, err := exec.Command("zstd", "-dc", filepath.Join(vectors, "shapes.zst")).Output()
		if err != nil {
			loadEr = err
			return
		}
		shapes = out
		keys, loadEr = LoadKeys(shapes)
	})
	if loadEr != nil {
		t.Fatalf("load keys: %v (the zstd tool is needed to read shapes.zst)", loadEr)
	}
	return keys
}

type fixture struct {
	st        Statement
	issuer    []byte
	seed      []byte
	devSig    []byte
	pseudonym []byte
	refProof  []byte
}

func load(t testing.TB) fixture {
	t.Helper()
	var req, nym map[string]any
	if err := json.Unmarshal(read(t, "verifier.json"), &req); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(read(t, "pseudonym.json"), &nym); err != nil {
		t.Fatal(err)
	}
	xy := strings.Split(req["issuer_key"].(string), ",")
	m := req["mdoc"].(map[string]any)
	v := nym["verifiers"].([]any)[0].(map[string]any)
	vm := v["mdoc"].(map[string]any)
	cred, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(read(t, "nym-auth-mdoc.txt"))))
	if err != nil {
		t.Fatal(err)
	}
	return fixture{
		st: Statement{
			IssuerKeyX: unhex(t, xy[0]), IssuerKeyY: unhex(t, xy[1]),
			Time: m["time"].(string), Earliest: m["earliest"].(string), Cutoff: m["cutoff"].(string),
			ChallengeDigest: unhex(t, vm["challenge_digest"].(string)),
			VerifierInput:   unhex(t, v["verifier_input"].(string)),
		},
		issuer:    cred,
		seed:      unhex(t, nym["holder"].(map[string]any)["test_seed"].(string)),
		devSig:    unhex(t, vm["device_signature"].(string)),
		pseudonym: unhex(t, v["pseudonym"].(string)),
		refProof:  read(t, "reference-proof.bin"),
	}
}

func want(t *testing.T, err error, s Status) {
	t.Helper()
	if err == nil || StatusOf(err) != s {
		t.Fatalf("want status %d, got %v", s, err)
	}
}

func TestHonestVerifyOfTheReferenceProof(t *testing.T) {
	f := load(t)
	got, err := loaded(t).Verify(&f.st, f.refProof)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, f.pseudonym) {
		t.Fatalf("pseudonym %x, want %x", got, f.pseudonym)
	}
}

func TestProveThenVerifyAndTheSeedIsZeroed(t *testing.T) {
	f := load(t)
	h := &Holder{IssuerSigned: f.issuer, SecretSeed: append([]byte(nil), f.seed...), DeviceSignature: f.devSig}
	proof, pseudonym, err := loaded(t).Prove(&f.st, h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pseudonym, f.pseudonym) || len(proof) < 90000 {
		t.Fatalf("pseudonym %x, %d proof bytes", pseudonym, len(proof))
	}
	if !bytes.Equal(h.SecretSeed, make([]byte, 16)) {
		t.Fatal("the seed was not zeroed")
	}
	got, err := loaded(t).Verify(&f.st, proof)
	if err != nil || !bytes.Equal(got, f.pseudonym) {
		t.Fatalf("verify: %x %v", got, err)
	}
}

func TestTamperedInputsAreRefused(t *testing.T) {
	k := loaded(t)
	f := load(t)

	other := f.st
	other.VerifierInput = unhex(t, "5ff3c35cfed806981de9ad610c4a7fe100867aee4530485aed3a0cc6e71f22b1")
	_, err := k.Verify(&other, f.refProof)
	want(t, err, Mismatch)

	other = f.st
	other.ChallengeDigest = append([]byte(nil), f.st.ChallengeDigest...)
	other.ChallengeDigest[0] ^= 1
	_, err = k.Verify(&other, f.refProof)
	want(t, err, Mismatch)

	other = f.st
	other.IssuerKeyY = append([]byte(nil), f.st.IssuerKeyY...)
	other.IssuerKeyY[31] ^= 1 // off the curve
	_, err = k.Verify(&other, f.refProof)
	want(t, err, InvalidInput)

	other = f.st
	other.Earliest, other.Cutoff = "1990-05-17", "1990-05-17" // a one-day window
	_, err = k.Verify(&other, f.refProof)
	want(t, err, InvalidInput)

	damaged := append([]byte(nil), f.refProof...)
	damaged[len(damaged)/2] ^= 1
	if _, err = k.Verify(&f.st, damaged); err == nil {
		t.Fatal("a damaged proof was accepted")
	}
	_, err = k.Verify(&f.st, append(append([]byte(nil), f.refProof...), 0))
	want(t, err, InvalidInput)

	// prove: a wrong seed and a wrong device signature are refused by code
	h := &Holder{IssuerSigned: f.issuer, SecretSeed: append([]byte(nil), f.seed...), DeviceSignature: f.devSig}
	h.SecretSeed[0] ^= 1
	_, _, err = k.Prove(&f.st, h)
	want(t, err, RefusedSeedMismatch)
	h = &Holder{IssuerSigned: f.issuer, SecretSeed: append([]byte(nil), f.seed...), DeviceSignature: append([]byte(nil), f.devSig...)}
	h.DeviceSignature[3] ^= 1
	_, _, err = k.Prove(&f.st, h)
	want(t, err, RefusedDeviceSignature)
}

func TestUnapprovedShapesAndBadArguments(t *testing.T) {
	loaded(t)
	bad := append([]byte(nil), shapes...)
	bad[len(bad)/2] ^= 1
	_, err := LoadKeys(bad)
	want(t, err, UnknownCircuit)
	_, err = LoadKeys(nil)
	want(t, err, UnknownCircuit)
	// a nil keys handle and an empty statement are invalid arguments, not crashes
	f := load(t)
	_, err = (&Keys{}).Verify(&f.st, f.refProof)
	want(t, err, InvalidArg)
	_, err = keys.Verify(&Statement{}, f.refProof)
	want(t, err, InvalidInput)
	_, err = keys.Verify(&f.st, nil)
	want(t, err, InvalidInput)
}

func TestSharedChallengeVectors(t *testing.T) {
	var v struct {
		Derive []struct {
			Origin, Nonce, DocType string
			Thumb                  *string `json:"jwk_thumbprint_hex"`
			Transcript             string  `json:"session_transcript_hex"`
			Digest                 string  `json:"challenge_digest_hex"`
		} `json:"derive"`
		Digest []struct {
			Transcript string `json:"session_transcript_hex"`
			DocType    string `json:"doc_type"`
			Digest     string `json:"challenge_digest_hex"`
		} `json:"digest"`
		Rejects []struct {
			Name       string
			Op         string
			Origin     string
			Nonce      string
			DocType    string  `json:"doc_type"`
			Thumb      *string `json:"jwk_thumbprint_hex"`
			Transcript string  `json:"session_transcript_hex"`
		} `json:"rejects"`
	}
	raw := read(t, "challenge-vectors.json")
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	// the JSON keys origin/nonce/doc_type are lower case; decode them explicitly
	var generic struct {
		Derive []map[string]any `json:"derive"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for i, c := range generic.Derive {
		var thumb []byte
		if s, ok := c["jwk_thumbprint_hex"].(string); ok {
			thumb = unhex(t, s)
		}
		e2, st, err := DeriveChallenge(c["origin"].(string), c["nonce"].(string), c["doc_type"].(string), thumb)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(e2) != v.Derive[i].Digest || hex.EncodeToString(st) != v.Derive[i].Transcript {
			t.Fatalf("vector %d: e2 %x transcript %x", i, e2, st)
		}
	}
	for _, c := range v.Digest {
		d, err := ChallengeDigest(unhex(t, c.Transcript), c.DocType)
		if err != nil || hex.EncodeToString(d) != c.Digest {
			t.Fatalf("digest vector: %x %v", d, err)
		}
	}
	for _, c := range v.Rejects {
		var err error
		switch c.Op {
		case "derive":
			var thumb []byte
			if c.Thumb != nil {
				thumb = unhex(t, *c.Thumb)
			}
			_, _, err = DeriveChallenge(c.Origin, c.Nonce, c.DocType, thumb)
		default:
			_, err = ChallengeDigest(unhex(t, c.Transcript), c.DocType)
		}
		if err == nil {
			t.Fatalf("reject vector %q was accepted", c.Name)
		}
	}
}

func TestVerifierInput(t *testing.T) {
	f := load(t)
	vi, err := VerifierInput("x509_san_dns:verifier.example")
	if err != nil || !bytes.Equal(vi, f.st.VerifierInput) {
		t.Fatalf("%x %v", vi, err)
	}
	if _, err := VerifierInput(""); err == nil {
		t.Fatal("an empty client_id was accepted")
	}
}
