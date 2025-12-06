package main

import (
	"bytes"
	"database/sql"
	"io"
	"log"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := NewSecureDB("./config.db", "./keyring.asc")
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
	db        *sql.DB
	publicKey *openpgp.Entity
	secretKey *openpgp.Entity
}

func NewSecureDB(dbPath, keyringPath string) (*SecureDB, error) {
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

	// Load GPG keyring
	keyringFile, err := os.Open(keyringPath)
	if err != nil {
		return nil, err
	}
	defer keyringFile.Close()

	entityList, err := openpgp.ReadArmoredKeyRing(keyringFile)
	if err != nil {
		return nil, err
	}

	return &SecureDB{
		db:        db,
		publicKey: entityList[0],
		secretKey: entityList[0],
	}, nil
}

// Encrypt data with GPG
func (s *SecureDB) encrypt(plaintext []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, []*openpgp.Entity{s.publicKey},
		nil, nil, nil)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(plaintext)
	if err != nil {
		return nil, err
	}
	w.Close()

	return buf.Bytes(), nil
}

// Decrypt GPG-encrypted data
func (s *SecureDB) decrypt(ciphertext []byte) ([]byte, error) {
	md, err := openpgp.ReadMessage(bytes.NewReader(ciphertext),
		openpgp.EntityList{s.secretKey}, nil, nil)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(md.UnverifiedBody)
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
