# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**kubecerts** is a Go CLI tool for managing Kubernetes PKI certificates in NixOS-based infrastructure. It discovers Kubernetes hosts from Nix configurations, generates Certificate Authorities (CAs), and manages certificate lifecycle with Age encryption support.

## Build and Run Commands

```bash
# Build the application
go build -o kubecerts

# Run directly
go run main.go

# Format code
go fmt ./...

# Run static analysis
go vet ./...

# Tidy dependencies
go mod tidy

# Enter development environment (requires DevBox)
devbox shell
```

## CLI Commands

The tool provides these main commands:

```bash
# List discovered hosts
./kubecerts hosts

# Check certificate status
./kubecerts status --age-key path/to/key.age

# Renew CA certificates  
./kubecerts renew ca [ca-type|all] --age-key path/to/key.age
```

Common flags:
- `--flake, -f`: Path to Nix flake (default: ".")
- `--secrets-dir, -s`: Secrets directory containing encrypted certificates (default: "./secrets")
- `--age-key, -k`: Path to age identity file (required for most operations)
- `--format`: Output format for status: text, json, yaml (default: "text")

## Architecture

### Package Structure

```
pkg/
├── ca/          # Certificate generation and CA types
├── manager/     # Main orchestration and business logic
├── nix/         # Nix flake parsing for host discovery
├── age/         # Age encryption/decryption handling
├── sync/        # Certificate deployment and synchronization
└── types/       # Common types (Host) to avoid circular dependencies
```

### Key Design Decisions

1. **Shared CA Generation**: CA certificates are generated once and deployed to all hosts (not per-host)
2. **CSR Validation**: Validates certificates against expected CSR format generated on-the-fly (no CSR persistence)
3. **Certificate Consistency**: Status command checks if certificates are identical across hosts using SHA256 fingerprints
4. **Age Encryption**: All certificates are stored encrypted with Age in the secrets directory

### ⚠️ CRITICAL: CA Certificate Generation Rules

**DO NOT** add host information parameters to CA generation methods:
- CA certificates are **cluster-wide** and must be identical across all hosts
- Host-specific information (hostname, IP, role) is NOT needed for CA certificates
- Always generate CA certificates first, then deploy the same certificate to all hosts

**Correct approach**:
```go
// ✅ GOOD - No host information needed
func GenerateCAExpectedCSR(caType CAType) (*x509.CertificateRequest, error)
func GenerateSharedCA(caType CAType) (*x509.Certificate, *rsa.PrivateKey, error)

// ❌ BAD - Don't do this
func GenerateCA(caType CAType, hostInfo HostInfo) // Host info not needed for CAs!
```

**Root CA Certificate Properties**:
- Root CA certificates do NOT require KeyUsage fields - they are self-signed root certificates
- The current KeyUsage fields in the code may be unnecessary and could be removed
- What matters is: IsCA: true, BasicConstraintsValid: true, and proper Subject fields

### Certificate File Structure

Certificates are stored in: `secrets/{system}/{host}/kubernetes/pki/`
- Kubernetes CA: `ca.crt.age`
- ETCD CA: `etcd/ca.crt.age`
- Front Proxy CA: `front-proxy-ca.crt.age`

### Important Implementation Details

1. **Host Discovery**: Uses `nix eval` to parse NixOS configurations and find Kubernetes-enabled hosts
2. **CA Types**: Supports three CA types - kubernetes-ca, etcd-ca, kubernetes-front-proxy-ca
3. **Validation**: Certificates are validated against expected format (Organization: "Kubernetes", proper Common Names)
4. **10-Year Validity**: CA certificates are generated with 10-year validity period

## Development Patterns

### Error Handling
```go
// Always wrap errors with context
if err != nil {
    return nil, fmt.Errorf("failed to do X: %w", err)
}
```

### CA Certificate Properties
- Organization: "Kubernetes"
- Country: "US"
- Validity: 10 years
- Key Usage: CertSign | CRLSign | DigitalSignature
- Extended Key Usage: ServerAuth, ClientAuth

### Testing Nix Integration
```bash
# Test host discovery
nix eval --json .#nixosConfigurations --apply "builtins.attrNames"

# Check specific host
nix eval ".#nixosConfigurations.hostname.config.capybara.app.server.kubernetes.enable"
```

## Common Development Tasks

When adding new features:
1. Check if it involves CA generation - use `GenerateCAExpectedCSR()` for consistency
2. For new commands, add to main.go CLI structure
3. Business logic goes in pkg/manager
4. Keep types in pkg/types to avoid circular dependencies

When debugging certificate issues:
1. Check file paths match expected structure
2. Verify age key permissions and access
3. Use status command to check consistency across hosts
4. CSR validation shows if certificates match expected format

## Key Files to Understand

- `main.go`: CLI entry point and command definitions
- `pkg/manager/manager.go`: Core business logic for status and renewal
- `pkg/ca/generator.go`: Certificate generation logic
- `pkg/nix/flake.go`: Nix configuration parsing