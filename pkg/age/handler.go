package age

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
)

type Config struct {
	IdentityPath string
}

type Handler struct {
	identities []age.Identity
}

func NewHandler(keyPath string) (*Handler, error) {
	// Expand tilde in path
	if strings.HasPrefix(keyPath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		keyPath = filepath.Join(homeDir, keyPath[2:])
	}

	keyFile, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open age key file at %s: %w", keyPath, err)
	}
	defer keyFile.Close()

	// Try to parse as age identities first
	identities, err := age.ParseIdentities(keyFile)
	if err != nil {
		// If that fails, try parsing as SSH key
		keyFile.Seek(0, 0)
		pemBytes, readErr := io.ReadAll(keyFile)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", keyPath, readErr)
		}
		
		sshIdentity, sshErr := agessh.ParseIdentity(pemBytes)
		if sshErr != nil {
			return nil, fmt.Errorf("failed to parse as age key (%v) or SSH key (%v) from %s", err, sshErr, keyPath)
		}
		identities = []age.Identity{sshIdentity}
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no valid age identities found in %s", keyPath)
	}

	return &Handler{
		identities: identities,
	}, nil
}

func (h *Handler) GetRecipients() ([]age.Recipient, error) {
	recipients := make([]age.Recipient, 0, len(h.identities))
	
	for _, identity := range h.identities {
		// Type assert to get the recipient method
		switch id := identity.(type) {
		case *age.X25519Identity:
			recipients = append(recipients, id.Recipient())
		case *agessh.Ed25519Identity:
			recipients = append(recipients, id.Recipient())
		case *agessh.RSAIdentity:
			recipients = append(recipients, id.Recipient())
		default:
			return nil, fmt.Errorf("unsupported identity type: %T", identity)
		}
	}
	
	return recipients, nil
}

func (h *Handler) DecryptFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()

	var reader io.Reader = file
	
	// Check if file is armored
	fileContent, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	
	if strings.HasPrefix(string(fileContent), "-----BEGIN AGE ENCRYPTED FILE-----") {
		reader = armor.NewReader(strings.NewReader(string(fileContent)))
	} else {
		reader = strings.NewReader(string(fileContent))
	}

	ageReader, err := age.Decrypt(reader, h.identities...)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file: %w", err)
	}

	data, err := io.ReadAll(ageReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return data, nil
}

func (h *Handler) EncryptData(data []byte, recipients ...age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients provided")
	}

	var buf strings.Builder
	armorWriter := armor.NewWriter(&buf)
	
	ageWriter, err := age.Encrypt(armorWriter, recipients...)
	if err != nil {
		return nil, fmt.Errorf("failed to create age writer: %w", err)
	}

	if _, err := ageWriter.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := ageWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close age writer: %w", err)
	}

	if err := armorWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close armor writer: %w", err)
	}

	return []byte(buf.String()), nil
}