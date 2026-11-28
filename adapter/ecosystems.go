// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

// This file defines shared PURL ecosystem and cryptographic digest algorithm
// constants so provider adapters declare SupportedInputs without hardcoding
// raw strings (#70, #71, #96).

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
