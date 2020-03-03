package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/transit"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

func Test_EncryptDecrypt(t *testing.T) {
	// iv is the initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	// key is the AES key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader([]byte("reader"))

	// encrypt
	encr, err := EncryptReader(r, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	// decrypt
	decr, err := EncryptReader(encr, key, iv)
	if err != nil {
		log.Fatal(err)
	}

	result, err := ioutil.ReadAll(decr)
	if err != nil {
		log.Fatal(err)
	}

	if string(result) != "reader" {
		t.Fatalf("decrypted value mismatch want=%s got=%s", "reader", string(result))
	}
}

func Test_PostAndDecrypt(t *testing.T) {
	// iv is the initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	// key is the AES key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	var receivedData []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedData, err = ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}

		w.Write(receivedData)
	}))
	defer ts.Close()

	r := bytes.NewReader([]byte("reader"))

	encr, err := EncryptReader(r, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(ts.URL, "application/octet-stream", encr)
	if err != nil {
		log.Fatal(err)
	}

	t.Logf("Ciphertext=%s", hex.Dump(receivedData))
	if bytes.Equal(receivedData, []byte("reader")) {
		log.Fatal("no encryption was done, output equals input")
	}

	decr, err := EncryptReader(resp.Body, key, iv)
	if err != nil {
		log.Fatal(err)
	}

	result, err := ioutil.ReadAll(decr)
	if err != nil {
		log.Fatal(err)
	}

	if string(result) != "reader" {
		t.Fatalf("decrypted value mismatch want=%s got=%s", "reader", string(result))
	}
}

func Test_PipeAndEncryptRequestThrough(t *testing.T) {
	// iv is the initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	// key is the AES key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	unencryptedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "very sensitive string")
	}))
	defer unencryptedServer.Close()

	var receivedData []byte
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedData, err = ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}

		w.Write(receivedData)
	}))
	defer targetServer.Close()

	unencryptedResp, err := http.Get(unencryptedServer.URL)
	if err != nil {
		log.Fatal(err)
	}

	encr, err := EncryptReader(unencryptedResp.Body, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(targetServer.URL, "application/octet-stream", encr)
	if err != nil {
		log.Fatal(err)
	}

	t.Logf("Ciphertext=\n%s", hex.Dump(receivedData))
	if bytes.Equal(receivedData, []byte("very sensitive string\n")) {
		log.Fatal("no encryption was done, output equals input")
	}

	decr, err := EncryptReader(resp.Body, key, iv)
	if err != nil {
		log.Fatal(err)
	}

	result, err := ioutil.ReadAll(decr)
	if err != nil {
		log.Fatal(err)
	}

	if string(result) != "very sensitive string\n" {
		t.Fatalf("decrypted value mismatch want=%s got=%s", "very sensitive string\n", string(result))
	}
}

func Test_VaultDatakey_EncryptDecrypt(t *testing.T) {
	_, keyData, closer := setupTransitKey(t)
	defer closer()

	key := keyData["rawplaintext"].([]byte)

	// iv is the initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader([]byte("reader"))

	// encrypt
	encr, err := EncryptReader(r, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	// decrypt
	decr, err := EncryptReader(encr, key, iv)
	if err != nil {
		log.Fatal(err)
	}

	result, err := ioutil.ReadAll(decr)
	if err != nil {
		log.Fatal(err)
	}

	if string(result) != "reader" {
		t.Fatalf("decrypted value mismatch want=%s got=%s", "reader", string(result))
	}
}

func Test_VaultDatakey_Management(t *testing.T) {
	client, keyData, closer := setupTransitKey(t)
	defer closer()

	s, err := client.Logical().Write("transit/decrypt/my-key", map[string]interface{}{
		"ciphertext": keyData["ciphertext"],
	})
	if err != nil {
		t.Fatal(err)
	}

	s.Data["rawplaintext"], err = base64.StdEncoding.DecodeString(s.Data["plaintext"].(string))
	if err != nil {
		t.Fatal(err)
	}

	if s.Data["plaintext"].(string) != keyData["plaintext"].(string) {
		t.Fatal("decrypted value mismatch")
	}

	if !bytes.Equal(s.Data["rawplaintext"].([]byte), keyData["rawplaintext"].([]byte)) {
		t.Fatal("decoded plaintext value mismatch")
	}
}

func setupTransitKey(t *testing.T) (*api.Client, map[string]interface{}, func()) {
	client, closer := createTestVault(t)

	err := client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("transit/keys/my-key", map[string]interface{}{
		"type": "chacha20-poly1305",
	})
	if err != nil {
		t.Fatal(err)
	}

	s, err := client.Logical().Write("transit/datakey/plaintext/my-key", map[string]interface{}{
		"bits": 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	s.Data["rawplaintext"], err = base64.StdEncoding.DecodeString(s.Data["plaintext"].(string))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("plaintext key: %v", s.Data)

	return client, s.Data, closer
}

// createTestVault creates a in-memory vault server
// from https://stackoverflow.com/questions/57771228/mocking-hashicorp-vault-in-go
func createTestVault(t *testing.T) (*api.Client, func()) {
	t.Helper()

	// Create an in-memory, unsealed core (the "backend", if you will).
	core, _, rootToken := vault.TestCoreUnsealedWithConfig(t, &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": transit.Factory,
		},
	})

	// Start an HTTP server for the core.
	ln, addr := vaulthttp.TestServer(t, core)

	// Create a client that talks to the server, initially authenticating with
	// the root token.
	conf := api.DefaultConfig()
	conf.Address = addr

	client, err := api.NewClient(conf)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(rootToken)

	return client, func() {
		_ = ln.Close()
	}
}
