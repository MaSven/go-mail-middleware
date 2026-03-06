package main

import (
	"fmt"
	"log"
	"os"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail-middleware/openpgp"
)

func testKey(isPrivate bool) string {

	pgp := crypto.PGP()

	key, err := pgp.KeyGeneration().AddUserId("alice", "alice@alice.com").New().GenerateKey()
	if err != nil {
		log.Fatalf("Could not create key for testcases %v", err)
	}

	if isPrivate {
		priv, err := key.Armor()
		if err != nil {
			log.Fatalf("Could not create public test key %v", err)
		}
		return priv
	}

	pub, err := key.GetArmoredPublicKey()
	if err != nil {
		log.Fatalf("Could not create public test key %v", err)
	}
	return pub

}

func main() {
	// First we need a config for our OpenPGP middleware
	//
	// In case your public key is in byte slice format or even a file, we provide two
	// helper methods:
	// - openpgp.NewConfigFromPubKeyBytes()
	// - openpgp.NewConfigFromPubKeyFile()
	//
	pubKey := testKey(false)
	privKey := testKey(true)
	mc, err := openpgp.NewConfig(privKey, pubKey, openpgp.WithScheme(openpgp.SchemePGPMIME))
	if err != nil {
		fmt.Printf("failed to create new config: %s\n", err)
		os.Exit(1)
	}
	mw := openpgp.NewMiddleware(mc)

	// Finally we create a new mail.Msg with our middleware assigned
	m := mail.NewMsg(mail.WithMiddleware(mw))
	if err := m.From("toni.sender@example.com"); err != nil {
		log.Fatalf("failed to set From address: %s", err)
	}
	if err := m.To("tina.recipient@example.com"); err != nil {
		log.Fatalf("failed to set To address: %s", err)
	}
	m.Subject("This is my first mail with go-mail!")
	m.SetBodyString(mail.TypeTextPlain, "Do you like this mail? I certainly do!")
	m.AttachFile("./test", mail.WithFileContentType("text/plain"))
	m.SetPGPType(mail.PGPEncrypt)
	c, err := mail.NewClient("localhost", mail.WithPort(1025),
		mail.WithSMTPAuth(mail.SMTPAuthNoAuth),
		mail.WithUsername("my_username"), mail.WithPassword("extremely_secret_pass"), mail.WithTLSPolicy(mail.TLSOpportunistic))
	if err != nil {
		log.Fatalf("failed to create mail client: %s", err)
	}
	if err := c.DialAndSend(m); err != nil {
		log.Fatalf("failed to send mail: %s", err)
	}

}
