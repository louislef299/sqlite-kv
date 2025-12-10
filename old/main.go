package main

import (
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := NewSecureDB("./config.db", "./key.bin")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Store encrypted data
	db.Set("session.token", "secret-token-value")

	// Retrieve and decrypt data
	token, err := db.Get("session.token")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Token:", token)
}

type SecureDB struct {
	db    *sql.DB
	aead  cipher.AEAD
}

func NewSecureDB(dbPath, keyPath string) (*SecureDB, error) {
	// Open database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value BLOB
    )`)
	if err != nil {
		return nil, err
	}

	// Load encryption key (32 bytes for ChaCha20-Poly1305)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}

	// Create XChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	return &SecureDB{
		db:   db,
		aead: aead,
	}, nil
}

// Encrypt data with ChaCha20-Poly1305
func (s *SecureDB) encrypt(plaintext []byte) ([]byte, error) {
	// Generate a random nonce (24 bytes for XChaCha20-Poly1305)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate the plaintext
	// The result is: nonce || ciphertext || tag
	ciphertext := s.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt ChaCha20-Poly1305 encrypted data
func (s *SecureDB) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := s.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	// Decrypt and verify the authentication tag
	plaintext, err := s.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Store encrypted value
func (s *SecureDB) Set(key, value string) error {
	encrypted, err := s.encrypt([]byte(value))
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
		key, encrypted)
	return err
}

// Retrieve and decrypt value
func (s *SecureDB) Get(key string) (string, error) {
	var encrypted []byte
	err := s.db.QueryRow(
		"SELECT value FROM config WHERE key = ?", key).Scan(&encrypted)
	if err != nil {
		return "", err
	}

	decrypted, err := s.decrypt(encrypted)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func (s *SecureDB) Close() error {
	return s.db.Close()
}
