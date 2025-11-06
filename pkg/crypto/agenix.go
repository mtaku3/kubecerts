package crypto

import (
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/agessh"
)

const (
	DefaultIdentityFile = "/var/lib/agenix/agenix_ed25519"
)


// AgenixCrypto handles encryption and decryption using age
type AgenixCrypto struct {
	identityFile string
	identity     age.Identity
	recipient    age.Recipient
}

// NewAgenixCrypto creates a new AgenixCrypto instance
func NewAgenixCrypto(identityFile string) (*AgenixCrypto, error) {
	if identityFile == "" {
		identityFile = DefaultIdentityFile
	}

	keyFile, err := os.Open(identityFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open age key file at %s: %w", identityFile, err)
	}
	defer keyFile.Close()

	// Try to parse as age identities first
	identities, err := age.ParseIdentities(keyFile)
	if err != nil {
		// If that fails, try parsing as SSH key
		keyFile.Seek(0, 0)
		pemBytes, readErr := io.ReadAll(keyFile)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", identityFile, readErr)
		}
		
		sshIdentity, sshErr := agessh.ParseIdentity(pemBytes)
		if sshErr != nil {
			return nil, fmt.Errorf("failed to parse as age key (%v) or SSH key (%v) from %s", err, sshErr, identityFile)
		}
		identities = []age.Identity{sshIdentity}
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no valid identities found in %s", identityFile)
	}

	// Use the first identity
	identity := identities[0]

	// Derive the recipient from the identity
	var recipient age.Recipient
	switch id := identity.(type) {
	case *age.X25519Identity:
		recipient = id.Recipient()
	case *agessh.Ed25519Identity:
		recipient = id.Recipient()
	case *agessh.RSAIdentity:
		recipient = id.Recipient()
	default:
		return nil, fmt.Errorf("unsupported identity type: %T", identity)
	}

	return &AgenixCrypto{
		identityFile: identityFile,
		identity:     identity,
		recipient:    recipient,
	}, nil
}

// Encrypt encrypts data using age
func (ac *AgenixCrypto) Encrypt(data []byte) ([]byte, error) {
	var encryptedData []byte
	
	// Create a buffer to hold the encrypted data
	buf := &writeBuffer{data: &encryptedData}
	
	// Create an armored writer for ASCII output
	armoredWriter := armor.NewWriter(buf)
	defer armoredWriter.Close()
	
	// Create an age writer
	writer, err := age.Encrypt(armoredWriter, ac.recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to create age writer: %w", err)
	}
	defer writer.Close()
	
	// Write the data
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write encrypted data: %w", err)
	}
	
	// Close the writer to finalize encryption
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close age writer: %w", err)
	}
	
	// Close the armored writer
	if err := armoredWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close armored writer: %w", err)
	}
	
	return encryptedData, nil
}

// Decrypt decrypts data using age
func (ac *AgenixCrypto) Decrypt(encryptedData []byte) ([]byte, error) {
	// Create an armored reader
	armoredReader := armor.NewReader(newReadSeeker(encryptedData))
	
	// Create an age reader
	reader, err := age.Decrypt(armoredReader, ac.identity)
	if err != nil {
		return nil, fmt.Errorf("failed to create age reader: %w", err)
	}
	
	// Read all decrypted data
	decryptedData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}
	
	return decryptedData, nil
}

// GetRecipient returns the public key recipient
func (ac *AgenixCrypto) GetRecipient() age.Recipient {
	return ac.recipient
}

// writeBuffer implements io.Writer for collecting bytes
type writeBuffer struct {
	data *[]byte
}

func (wb *writeBuffer) Write(p []byte) (n int, err error) {
	*wb.data = append(*wb.data, p...)
	return len(p), nil
}

// readSeeker provides io.ReadSeeker interface for byte slices
type readSeeker struct {
	data []byte
	pos  int64
}

func newReadSeeker(data []byte) *readSeeker {
	return &readSeeker{data: data}
}

func (rs *readSeeker) Read(p []byte) (n int, err error) {
	if rs.pos >= int64(len(rs.data)) {
		return 0, io.EOF
	}
	n = copy(p, rs.data[rs.pos:])
	rs.pos += int64(n)
	return n, nil
}

func (rs *readSeeker) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		rs.pos = offset
	case io.SeekCurrent:
		rs.pos += offset
	case io.SeekEnd:
		rs.pos = int64(len(rs.data)) + offset
	default:
		return 0, fmt.Errorf("invalid whence")
	}
	if rs.pos < 0 {
		rs.pos = 0
	}
	return rs.pos, nil
}
