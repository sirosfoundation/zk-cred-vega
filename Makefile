# zk-cred-vega Makefile — UniFFI binding generation & Android cross-compilation
#
# Mirrors zk-cred-longfellow's own Makefile (same org, same UniFFI/cross-
# compile shape, itself adapted from siros-wscd-manager's). Kotlin/Android
# only for this pass, per the tracked plan ("Kotlin first") — no iOS/
# XCFramework targets here yet.
#
# Targets:
#   make bindings-kotlin — generate Kotlin bindings from the host library
#   make android          — cross-compile for Android (arm64, armv7, x86_64)
#   make aar               — package Android AAR
#   make publish-local     — build AAR + POM and install to ~/.m2 (mavenLocal)
#   make go-cabi            — build the plain C-ABI cdylib/staticlib for Go's
#                             cgo verifier (default features, NOT
#                             --features uniffi), staged alongside the
#                             hand-written C header
#   make check-bindings    — CI helper: fail if generated bindings are stale
#   make clean              — remove build artifacts

CRATE_NAME := zk_cred_vega
LIB_NAME   := lib$(CRATE_NAME)
UNAME_S    := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  HOST_LIB_EXT := dylib
else
  HOST_LIB_EXT := so
endif
VERSION    := $(shell cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['version'])")

# Directories
BUILD_DIR    := target
BINDINGS_DIR := bindings
KOTLIN_DIR   := $(BINDINGS_DIR)/kotlin
GO_CABI_DIR  := $(BUILD_DIR)/go-cabi

# Android targets (via cargo-ndk)
ANDROID_TARGETS := aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

.PHONY: all bindings-kotlin android aar pom publish-local clean check-bindings dump-setup go-cabi

all: bindings-kotlin

# ── Setup-artifact generation (for go-zk-circuits publication) ───────

dump-setup:
	cargo run --release --bin dump_setup

# ── Binding generation ───────────────────────────────────────────────

bindings-kotlin: $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT)
	@mkdir -p $(KOTLIN_DIR)
	cargo run --release --features uniffi --bin uniffi-bindgen -- generate \
		--library $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language kotlin \
		--out-dir $(KOTLIN_DIR)
	@echo "Kotlin bindings generated in $(KOTLIN_DIR)"

$(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT):
	cargo build --release --features uniffi

# ── Go C-ABI (for vc-verifier's cgo wrapper) ────────────────────────
#
# Unlike bindings-kotlin (which needs --features uniffi), this builds with
# the crate's *default* features: go_ffi.rs is always compiled in (see
# src/lib.rs - no #[cfg(feature = "uniffi")] on that module, unlike
# ffi_api.rs), and building without uniffi keeps this artifact free of
# UniFFI's scaffolding and its extra dependency graph, which Go/cgo callers
# have no use for. Mirrors zk-cred-longfellow's own go-cabi target exactly.

go-cabi: $(GO_CABI_DIR)/$(LIB_NAME).$(HOST_LIB_EXT) $(GO_CABI_DIR)/$(LIB_NAME).a $(GO_CABI_DIR)/zk_cred_vega_go.h
	@echo "Go C-ABI library + header staged in $(GO_CABI_DIR)"

$(GO_CABI_DIR)/$(LIB_NAME).$(HOST_LIB_EXT): $(GO_CABI_DIR)/zk_cred_vega_go.h
	cargo build --release
	@mkdir -p $(GO_CABI_DIR)
	cp $(BUILD_DIR)/release/$(LIB_NAME).$(HOST_LIB_EXT) $(GO_CABI_DIR)/

$(GO_CABI_DIR)/$(LIB_NAME).a: $(GO_CABI_DIR)/zk_cred_vega_go.h
	cargo build --release
	@mkdir -p $(GO_CABI_DIR)
	cp $(BUILD_DIR)/release/$(LIB_NAME).a $(GO_CABI_DIR)/

$(GO_CABI_DIR)/zk_cred_vega_go.h: include/zk_cred_vega_go.h
	@mkdir -p $(GO_CABI_DIR)
	cp include/zk_cred_vega_go.h $(GO_CABI_DIR)/

# ── Android cross-compilation (requires cargo-ndk + Android NDK) ────

android: $(foreach t,$(ANDROID_TARGETS),android-$(t))

android-%:
	cargo ndk --target $* --platform 28 -- build --release --features uniffi

# ── AAR packaging ───────────────────────────────────────────────────

AAR_DIR := $(BUILD_DIR)/aar

aar: android
	@mkdir -p $(AAR_DIR)/jni/arm64-v8a $(AAR_DIR)/jni/armeabi-v7a $(AAR_DIR)/jni/x86_64
	cp $(BUILD_DIR)/aarch64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/arm64-v8a/
	cp $(BUILD_DIR)/armv7-linux-androideabi/release/$(LIB_NAME).so $(AAR_DIR)/jni/armeabi-v7a/
	cp $(BUILD_DIR)/x86_64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/x86_64/
	@echo '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.siros.zkcredvega"/>' \
		> $(AAR_DIR)/AndroidManifest.xml
	# The AAR only ships the native .so libraries; the UniFFI Kotlin bindings
	# are consumed as vendored source by the SDK, so an empty classes.jar
	# (required by the AAR layout) is sufficient. JNA is provided
	# transitively via the POM.
	@mkdir -p $(BUILD_DIR)/aar-classes/META-INF
	@printf 'Manifest-Version: 1.0\n' > $(BUILD_DIR)/aar-classes/META-INF/MANIFEST.MF
	cd $(BUILD_DIR)/aar-classes && zip -qr ../aar/classes.jar .
	cd $(AAR_DIR) && zip -r ../$(CRATE_NAME)-$(VERSION).aar .
	@echo "AAR created at $(BUILD_DIR)/$(CRATE_NAME)-$(VERSION).aar"

# ── Maven POM (for publishing the AAR by coordinates) ───────────────
MAVEN_GROUP    := org.siros
MAVEN_ARTIFACT := zk-cred-vega

pom:
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<project xmlns="http://maven.apache.org/POM/4.0.0"' \
	  '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
	  '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
	  '  <modelVersion>4.0.0</modelVersion>' \
	  '  <groupId>$(MAVEN_GROUP)</groupId>' \
	  '  <artifactId>$(MAVEN_ARTIFACT)</artifactId>' \
	  '  <version>$(VERSION)</version>' \
	  '  <packaging>aar</packaging>' \
	  '  <dependencies>' \
	  '    <dependency>' \
	  '      <groupId>net.java.dev.jna</groupId>' \
	  '      <artifactId>jna</artifactId>' \
	  '      <version>5.14.0</version>' \
	  '      <type>aar</type>' \
	  '    </dependency>' \
	  '  </dependencies>' \
	  '</project>' \
	  > $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom
	@echo "POM written to $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom"

# ── Local Maven install (mavenLocal / ~/.m2) ────────────────────────
# Coordinate: org.siros:zk-cred-vega:<version>
MAVEN_LOCAL_DIR := $(HOME)/.m2/repository/$(subst .,/,$(MAVEN_GROUP))/$(MAVEN_ARTIFACT)/$(VERSION)

publish-local: aar pom
	@mkdir -p $(MAVEN_LOCAL_DIR)
	cp $(BUILD_DIR)/$(CRATE_NAME)-$(VERSION).aar \
	   $(MAVEN_LOCAL_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).aar
	cp $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom \
	   $(MAVEN_LOCAL_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom
	@echo "Installed to $(MAVEN_LOCAL_DIR)"

# ── CI helper: verify bindings are up-to-date ───────────────────────

check-bindings: bindings-kotlin
	@git diff --exit-code $(BINDINGS_DIR) || \
		(echo "ERROR: Generated bindings are out of date. Run 'make bindings-kotlin' and commit." && exit 1)

# ── Clean ────────────────────────────────────────────────────────────

clean:
	cargo clean
	rm -rf $(BINDINGS_DIR) $(BUILD_DIR)/aar $(BUILD_DIR)/aar-classes
