package p2p

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"
)

// NewAuthenticatedTCPTransport pins committee Ed25519 keys in mutual TLS 1.3.
// Incoming message.From is bound to the authenticated connection identity.
// Metrics count framed application bytes; interface counters include TLS overhead.
func NewAuthenticatedTCPTransport(id NodeID, addr string, peers map[NodeID]string, buffer int, private ed25519.PrivateKey, public map[string]ed25519.PublicKey) (*TCPTransport, error) {
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(private.Public().(ed25519.PublicKey), public[string(id)]) {
		return nil, errors.New("TLS private key does not match committee identity")
	}
	pinned := make(map[string]ed25519.PublicKey, len(peers))
	seen := make(map[string]bool)
	for peer := range peers {
		key := public[string(peer)]
		if len(key) != ed25519.PublicKeySize || seen[string(key)] {
			return nil, errors.New("missing or duplicate TLS committee key")
		}
		pinned[string(peer)] = append(ed25519.PublicKey(nil), key...)
		seen[string(key)] = true
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: string(id)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		return nil, err
	}
	identity := func(state tls.ConnectionState) (NodeID, error) {
		if len(state.PeerCertificates) != 1 {
			return "", errors.New("TLS requires one pinned peer certificate")
		}
		cert := state.PeerCertificates[0]
		key, ok := cert.PublicKey.(ed25519.PublicKey)
		name := cert.Subject.CommonName
		if !ok || !bytes.Equal(key, pinned[name]) || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return "", errors.New("untrusted TLS committee identity")
		}
		return NodeID(name), nil
	}
	t := NewTCPTransport(id, addr, peers, buffer)
	t.peerIdentity = identity
	t.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, ClientAuth: tls.RequireAnyClientCert,
		// Authentication uses exact committee key pinning in VerifyConnection,
		// rather than DNS names or a public certificate authority.
		InsecureSkipVerify: true,
		VerifyConnection:   func(state tls.ConnectionState) error { _, err := identity(state); return err },
	}
	return t, nil
}
