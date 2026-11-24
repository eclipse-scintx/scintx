module github.com/yeeth-security/scintx

// Security: 1.26.10 is a patched Go release for the compromised eMudhra
// intermediate CAs (Oct 2026). CI and the SBOM job read this line
// (go-version-file), so they now build with the fixed toolchain too.
go 1.26.10

require gopkg.in/yaml.v3 v3.0.1

require (
	github.com/kr/pretty v0.3.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
