// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

import (
	"fmt"
	"slices"
	"strings"

	"github.com/eclipse-scintx/scintx/api"
)

// This file defines shared PURL ecosystem and cryptographic digest algorithm
// constants and shared PURL input validation so provider adapters do not
// duplicate ecosystem lists or PURL parsing logic (#70, #71, #96).

// Ecosystem identifies a standardized Package URL (PURL) ecosystem type.
type Ecosystem string

const (
	EcosystemNPM             Ecosystem = "npm"
	EcosystemPyPI            Ecosystem = "pypi"
	EcosystemMaven           Ecosystem = "maven"
	EcosystemGolang          Ecosystem = "golang"
	EcosystemCargo           Ecosystem = "cargo"
	EcosystemGem             Ecosystem = "gem"
	EcosystemNuGet           Ecosystem = "nuget"
	EcosystemComposer        Ecosystem = "composer"
	EcosystemHex             Ecosystem = "hex"
	EcosystemPub             Ecosystem = "pub"
	EcosystemSwift           Ecosystem = "swift"
	EcosystemCRAN            Ecosystem = "cran"
	EcosystemBioconductor    Ecosystem = "bioconductor"
	EcosystemHackage         Ecosystem = "hackage"
	EcosystemConan           Ecosystem = "conan"
	EcosystemCocoapods       Ecosystem = "cocoapods"
	EcosystemConda           Ecosystem = "conda"
	EcosystemDeb             Ecosystem = "deb"
	EcosystemAPK             Ecosystem = "apk"
	EcosystemRPM             Ecosystem = "rpm"
	EcosystemDebian          Ecosystem = "debian"
	EcosystemAlpine          Ecosystem = "alpine"
	EcosystemUbuntu          Ecosystem = "ubuntu"
	EcosystemRocky           Ecosystem = "rocky"
	EcosystemAlmaLinux       Ecosystem = "almalinux"
	EcosystemVSCodeExtension Ecosystem = "vscode-extension"
)

// DigestAlgorithm identifies a supported cryptographic hash algorithm (#68, #70).
type DigestAlgorithm string

const (
	DigestSHA256 DigestAlgorithm = "sha256"
	DigestSHA384 DigestAlgorithm = "sha384"
	DigestSHA512 DigestAlgorithm = "sha512"
)

// ValidateVersionedPURL verifies that rawPURL is non-empty, canonical, belongs
// to one of supportedEcosystems, and includes an explicit package version (#96).
func ValidateVersionedPURL(
	providerSlug string,
	rawPURL string,
	supportedEcosystems []Ecosystem,
) (canonicalPURL, version string, err error) {
	trimmed := strings.TrimSpace(rawPURL)
	if trimmed == "" {
		return "", "", &AdapterError{
			Code:    ErrUnsupportedInput,
			Message: providerSlug + " adapter requires a package PURL",
		}
	}
	canonical, err := api.CanonicalPurl(trimmed)
	if err != nil {
		return "", "", &AdapterError{
			Code:    ErrUnsupportedInput,
			Message: fmt.Sprintf("invalid package PURL: %v", err),
			Cause:   err,
		}
	}
	purlType, err := api.PurlType(canonical)
	if err != nil || !slices.Contains(supportedEcosystems, Ecosystem(purlType)) {
		return "", "", &AdapterError{
			Code:    ErrUnsupportedInput,
			Message: fmt.Sprintf("%s adapter does not support PURL ecosystem %q", providerSlug, purlType),
		}
	}
	ver, hasVersion, err := api.PurlVersion(canonical)
	if err != nil || !hasVersion {
		return "", "", &AdapterError{
			Code:    ErrUnsupportedInput,
			Message: providerSlug + " adapter requires a versioned package PURL",
		}
	}
	return canonical, ver, nil
}
