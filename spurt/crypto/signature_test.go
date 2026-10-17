package crypto

import "testing"

func TestNativeSignatureBindsMessageAndSigner(t *testing.T) {
	msg := []byte("Tyche beacon certificate")
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(kp.Private, msg)
	if !Verify(kp.Public, msg, sig) {
		t.Fatal("honest native signature rejected")
	}
	if Verify(kp.Public, []byte("other message"), sig) {
		t.Fatal("signature accepted for another message")
	}
	if Verify(other.Public, msg, sig) {
		t.Fatal("signature accepted for another signer")
	}
	sig[0] ^= 1
	if Verify(kp.Public, msg, sig) {
		t.Fatal("tampered signature accepted")
	}
}
