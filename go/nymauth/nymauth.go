// SPDX-License-Identifier: BSD-2-Clause

// Package nymauth is a thin cgo wrapper over the nymauth C ABI of zk-cred-vega
// (include/zk_cred_vega_nymauth_go.h): verify (and prove) a nym_auth age-range and pseudonym proof.
//
// Build the library first (`make go-cabi`, or `cargo build --release`). Override the search path
// with CGO_LDFLAGS / CGO_CFLAGS to use a staged copy.
//
// Contract: Time, ChallengeDigest and VerifierInput of a Statement must be the verifier's own,
// never taken from the holder or the presentation; derive ChallengeDigest with DeriveChallenge.
package nymauth

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lzk_cred_vega -Wl,-rpath,${SRCDIR}/../../target/release
#include <stdlib.h>
#include <string.h>
#include "zk_cred_vega_nymauth_go.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Status is a code of the C ABI.
type Status int32

const (
	OK                     Status = C.ZK_NYM_OK
	InvalidArg             Status = C.ZK_NYM_INVALID_ARG
	InvalidInput           Status = C.ZK_NYM_INVALID_INPUT
	InvalidShapes          Status = C.ZK_NYM_INVALID_SHAPES
	UnknownCircuit         Status = C.ZK_NYM_UNKNOWN_CIRCUIT
	ProverFailed           Status = C.ZK_NYM_PROVER_FAILED
	ProofInvalid           Status = C.ZK_NYM_PROOF_INVALID
	Mismatch               Status = C.ZK_NYM_MISMATCH
	Internal               Status = C.ZK_NYM_INTERNAL
	RefusedSeedMismatch    Status = C.ZK_NYM_REFUSED_SEED_MISMATCH
	RefusedIssuerSignature Status = C.ZK_NYM_REFUSED_ISSUER_SIGNATURE
	RefusedDeviceSignature Status = C.ZK_NYM_REFUSED_DEVICE_SIGNATURE
	RefusedCredential      Status = C.ZK_NYM_REFUSED_CREDENTIAL
)

// Error is a non-zero status.
type Error struct{ Status Status }

func (e *Error) Error() string { return fmt.Sprintf("nymauth: status %d", int32(e.Status)) }

// StatusOf returns the status of an error from this package, or Internal for any other.
func StatusOf(err error) Status {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return Internal
}

func check(s C.int32_t) error {
	if s == C.ZK_NYM_OK {
		return nil
	}
	return &Error{Status(s)}
}

// Keys is the resident circuit. Close it when done.
type Keys struct{ p *C.ZkNymKeys }

// LoadKeys builds the keys from the decompressed shapes; only approved shapes are accepted.
func LoadKeys(shapes []byte) (*Keys, error) {
	var p *C.ZkNymKeys
	var ptr *C.uint8_t
	if len(shapes) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&shapes[0]))
	}
	if err := check(C.zk_cred_vega_nymauth_load_keys(ptr, C.size_t(len(shapes)), &p)); err != nil {
		return nil, err
	}
	k := &Keys{p}
	runtime.SetFinalizer(k, func(k *Keys) { k.Close() })
	return k, nil
}

// Close releases the keys; it is safe to call twice.
func (k *Keys) Close() {
	if k.p != nil {
		C.zk_cred_vega_nymauth_free_keys(k.p)
		k.p = nil
	}
}

// Statement is what the verifier names.
type Statement struct {
	IssuerKeyX, IssuerKeyY []byte
	Time, Earliest, Cutoff string
	ChallengeDigest        []byte
	VerifierInput          []byte
}

// slice pins b for the call by copying it into C memory; free with the returned func.
func slice(b []byte) (C.ZkNymSlice, func()) {
	if len(b) == 0 {
		return C.ZkNymSlice{}, func() { /* nothing was allocated */ }
	}
	p := C.CBytes(b)
	return C.ZkNymSlice{ptr: (*C.uint8_t)(p), len: C.size_t(len(b))}, func() { C.free(p) }
}

func (s *Statement) c() (C.ZkNymStatement, func()) {
	var st C.ZkNymStatement
	var frees []func()
	set := func(dst *C.ZkNymSlice, b []byte) {
		v, f := slice(b)
		*dst = v
		frees = append(frees, f)
	}
	set(&st.issuer_key_x, s.IssuerKeyX)
	set(&st.issuer_key_y, s.IssuerKeyY)
	set(&st.time, []byte(s.Time))
	set(&st.earliest, []byte(s.Earliest))
	set(&st.cutoff, []byte(s.Cutoff))
	set(&st.challenge_digest, s.ChallengeDigest)
	set(&st.verifier_input, s.VerifierInput)
	return st, func() {
		for _, f := range frees {
			f()
		}
	}
}

// Verify accepts proof for the statement and returns the 32-byte pseudonym it reveals.
func (k *Keys) Verify(s *Statement, proof []byte) ([]byte, error) {
	st, free := s.c()
	defer free()
	pr, freeProof := slice(proof)
	defer freeProof()
	var out [32]byte
	err := check(C.zk_cred_vega_nymauth_verify(k.p, &st, pr.ptr, pr.len, (*C.uint8_t)(unsafe.Pointer(&out[0]))))
	runtime.KeepAlive(k)
	if err != nil {
		return nil, err
	}
	return out[:], nil
}

// Holder is what only the holder has; Prove zeroes SecretSeed.
type Holder struct {
	IssuerSigned    []byte
	SecretSeed      []byte
	DeviceSignature []byte
}

// Prove makes a proof and returns it with the pseudonym.
func (k *Keys) Prove(s *Statement, h *Holder) (proof, pseudonym []byte, err error) {
	st, free := s.c()
	defer free()
	is, f1 := slice(h.IssuerSigned)
	defer f1()
	ds, f2 := slice(h.DeviceSignature)
	defer f2()
	seed := newSeed(h.SecretSeed)
	// Wiped and freed on every way out, whatever the native call returned (it also zeroes the
	// buffer, but not when it refuses the arguments before it reaches the seed).
	defer freeSeed(seed, len(h.SecretSeed))
	ch := C.ZkNymHolder{issuer_signed: is, secret_seed: (*C.uint8_t)(seed), secret_seed_len: C.size_t(len(h.SecretSeed)), device_signature: ds}
	var p *C.uint8_t
	var n C.size_t
	var out [32]byte
	err = check(C.zk_cred_vega_nymauth_prove(k.p, &st, &ch, &p, &n, (*C.uint8_t)(unsafe.Pointer(&out[0]))))
	for i := range h.SecretSeed {
		h.SecretSeed[i] = 0
	}
	runtime.KeepAlive(k)
	if err != nil {
		return nil, nil, err
	}
	proof = C.GoBytes(unsafe.Pointer(p), C.int(n))
	C.zk_cred_vega_nymauth_free_buffer(p, n)
	return proof, out[:], nil
}

// DeriveChallenge returns e2 and the transcript seed (the SessionTranscript) for the verifier's
// request, per the circuits' SPEC.md section 3. jwkThumbprint is nil for an unencrypted response.
func DeriveChallenge(origin, nonce, docType string, jwkThumbprint []byte) (e2, sessionTranscript []byte, err error) {
	o, f1 := slice([]byte(origin))
	defer f1()
	n, f2 := slice([]byte(nonce))
	defer f2()
	d, f3 := slice([]byte(docType))
	defer f3()
	t, f4 := slice(jwkThumbprint)
	defer f4()
	var out [32]byte
	var p *C.uint8_t
	var l C.size_t
	if err := check(C.zk_cred_vega_nymauth_derive_challenge(o, n, d, t, &p, &l, (*C.uint8_t)(unsafe.Pointer(&out[0])))); err != nil {
		return nil, nil, err
	}
	st := C.GoBytes(unsafe.Pointer(p), C.int(l))
	C.zk_cred_vega_nymauth_free_buffer(p, l)
	return out[:], st, nil
}

// ChallengeDigest returns e2 for a SessionTranscript in hand.
func ChallengeDigest(sessionTranscript []byte, docType string) ([]byte, error) {
	s, f1 := slice(sessionTranscript)
	defer f1()
	d, f2 := slice([]byte(docType))
	defer f2()
	var out [32]byte
	if err := check(C.zk_cred_vega_nymauth_challenge_digest(s, d, (*C.uint8_t)(unsafe.Pointer(&out[0])))); err != nil {
		return nil, err
	}
	return out[:], nil
}

// VerifierInput returns SHA-256(clientID), the statement's VerifierInput.
func VerifierInput(clientID string) ([]byte, error) {
	c, f := slice([]byte(clientID))
	defer f()
	var out [32]byte
	if err := check(C.zk_cred_vega_nymauth_verifier_input(c, (*C.uint8_t)(unsafe.Pointer(&out[0])))); err != nil {
		return nil, err
	}
	return out[:], nil
}

// newSeed copies the seed into C memory.
func newSeed(b []byte) unsafe.Pointer { return C.CBytes(b) }

// wipeSeed zeroes n bytes of C memory.
func wipeSeed(p unsafe.Pointer, n int) {
	if p != nil && n > 0 {
		C.memset(p, 0, C.size_t(n))
	}
}

// freeSeed wipes the C copy of the seed, then frees it.
func freeSeed(p unsafe.Pointer, n int) {
	wipeSeed(p, n)
	C.free(p)
}

// peekSeed reads n bytes of C memory (tests).
func peekSeed(p unsafe.Pointer, n int) []byte { return C.GoBytes(p, C.int(n)) }
