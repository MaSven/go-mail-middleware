// SPDX-FileCopyrightText: 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package openpgp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	cryptov3 "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/emersion/go-message"
	"github.com/wneessen/go-mail"
)

const (
	// armorComment is the comment string used for the OpenPGP Armor
	armorComment = "https://go-mail.dev (OpenPGP based on: https://gopenpgp.org)"
	// armorVeersion is the version string used for the OpenPGP Armor
	armorVersion = "go-mail-middlware " + Version
)

// randomBoundary generates a random boundary string for use in MIME messages.
//
// This function creates a 30-byte random value using a cryptographic random number generator
// and formats it as a hexadecimal string.
//
// Returns:
//   - A string containing the generated random boundary.
//   - An error if reading from the random number generator fails.
func randomBoundary() (string, error) {
	var buf [30]byte
	_, err := io.ReadFull(rand.Reader, buf[:])
	if err != nil {
		return "", fmt.Errorf("failed to read from rand.Reader: %w", err)
	}
	return fmt.Sprintf("%x", buf[:]), nil
}

func pgpContentType() (map[string]string, error) {
	boundary, err := randomBoundary()
	if err != nil {
		return nil, err
	}

	return map[string]string{"protocol": "application/pgp-encrypted", "boundary": boundary, "charset": "UTF-8"}, nil
}

// Was getan werden muss
// Normale mail message bauen als multipart
// Danach dieses mit PGP als datei verschlüsseln
// Diese danach PP/MIME als neue nachricht setzen und die eigentliche msg als anhang
func (m *Middleware) pgpMime(msg *mail.Msg) *mail.Msg {
	pp := msg.GetParts()
	msg.SetPGPType(mail.PGPEncrypt)
	var messageBuffer bytes.Buffer
	var h message.Header
	innerBoundy, err := randomBoundary()
	if err != nil {
		m.config.Logger.Errorf("Could not create inner Boundary: %v", err)
		return msg
	}
	h.SetContentType(string(mail.TypeMultipartMixed), map[string]string{"boundary": innerBoundy})
	messageWriter, err := message.CreateWriter(&messageBuffer, h)
	if err != nil {
		m.config.Logger.Errorf("Failed to create first message part: %s", err)
		return msg
	}
	defer messageWriter.Close()

	for _, part := range pp {
		c, err := part.GetContent()
		var messagePart message.Header
		if err != nil {
			m.config.Logger.Errorf("failed to get part content: %s", err)
			continue
		}
		fmt.Printf("Message part %s", string(c))
		charset := part.GetCharset()
		messagePart.SetContentType(part.GetContentType().String(), map[string]string{"charset": charset.String()})
		messagePart.Header.Add(mail.HeaderContentTransferEnc.String(), mail.EncodingB64.String())
		messagePartWriter, err := messageWriter.CreatePart(messagePart)

		if err != nil {
			m.config.Logger.Errorf("failed to write message part: %s", err)
			continue
		}
		defer messagePartWriter.Close()
		io.Writer.Write(messagePartWriter, c)
	}
	// Attachments
	buf := bytes.Buffer{}
	af := msg.GetAttachments()
	msg.SetAttachments(nil)
	msg.UnsetAllParts()

	for _, f := range af {
		var messagePart message.Header
		_, err := f.Writer(&buf)
		if err != nil {
			m.config.Logger.Errorf("failed to write attachment to memory: %s", err)
			continue
		}

		messagePart.SetContentType(f.ContentType.String(), map[string]string{"name": f.Name})
		messagePart.SetContentDisposition("attachment", map[string]string{"filename": f.Name})
		messagePart.Header.Add(mail.HeaderContentTransferEnc.String(), mail.EncodingB64.String())
		messagePartWriter, err := messageWriter.CreatePart(messagePart)
		if err != nil {
			m.config.Logger.Errorf("Failed to write message part: %s", err)
			continue
		}
		defer messagePartWriter.Close()
		f.Writer(&buf)
		io.Writer.Write(messagePartWriter, buf.Bytes())
		buf.Reset()
	}
	pgp := cryptov3.PGPWithProfile(profile.RFC9580())

	encHandle, err := pgp.Encryption().Recipient(&m.config.V3PublicKey).SigningKey(&m.config.V3PrivateKy).New()
	if err != nil {
		m.config.Logger.Errorf("Could not create encryption handle %v", err)
	}
	pgpMessage, err := encHandle.Encrypt(messageBuffer.Bytes())

	if err != nil {
		m.config.Logger.Errorf("Could not encrypt message %v", err)
	}
	armored, err := pgpMessage.Armor()
	if err != nil {
		m.config.Logger.Errorf("Could not armor the message %v", err)
	}
	contenttype := `application/octet-stream; name="encrypted.asc"`

	msg.SetCharset("UTF-8")
	messagePart := msg.NewPart(mail.ContentType(contenttype), addDisposition(`inline; filename="encrypted.asc"`))
	messagePart.SetDescription("Openpgp encrypted message")
	messagePart.SetContent(armored)
	messagePart.SetCharset(mail.CharsetUTF8)
	messagePart.SetEncoding(mail.EncodingQP)
	mimePart := msg.NewPart(mail.ContentType("application/pgp-encrypted"), nil)
	mimePart.SetDescription("PGP/MIME version identifier")
	mimePart.SetContent("Version: 1")
	mimePart.SetEncoding(mail.EncodingQP)
	msg.SetParts([]*mail.Part{mimePart, messagePart})
	msg.SetMIMEVersion("1.0")
	return msg
}

func createWriter(content string) func(io.Writer) (int64, error) {
	return func(w io.Writer) (int64, error) {
		numBytes, err := w.Write([]byte(content))
		return int64(numBytes), err
	}
}

func addDisposition(disposition string) mail.PartOption {
	return func(p *mail.Part) {
		p.SetDisposition(disposition)
	}
}

// pgpInline takes the given mail.Msg and encrypts/signs the body parts
// and attachments and replaces them with an PGP encrypted data blob embedded
// into the mail body following the PGP/Inline scheme
func (m *Middleware) pgpInline(msg *mail.Msg) *mail.Msg {

	pp := msg.GetParts()
	for _, part := range pp {
		c, err := part.GetContent()
		if err != nil {
			m.config.Logger.Errorf("failed to get part content: %s", err)
			continue
		}
		switch part.GetContentType() {
		case mail.TypeTextPlain:
			s, err := m.processPlain(string(c))
			if err != nil {
				m.config.Logger.Errorf("failed to encrypt message part: %s", err)
				continue
			}
			part.SetEncoding(mail.EncodingB64)
			part.SetContent(s)
		default:
			m.config.Logger.Warnf("unsupported type %q. removing message part", string(part.GetContentType()))
			part.Delete()
		}
	}

	buf := bytes.Buffer{}
	ef := msg.GetEmbeds()
	msg.SetEmbeds(nil)
	for _, f := range ef {
		_, err := f.Writer(&buf)
		if err != nil {
			m.config.Logger.Errorf("failed to write attachment to memory: %s", err)
			continue
		}
		b, err := m.processBinary(buf.Bytes())
		if err != nil {
			m.config.Logger.Errorf("failed to encrypt attachment: %s", err)
			continue
		}
		if err := msg.EmbedReader(f.Name, bytes.NewReader([]byte(b))); err != nil {
			m.config.Logger.Errorf("failed to embed reader: %s", err)
			continue
		}
		buf.Reset()
	}
	af := msg.GetAttachments()
	msg.SetAttachments(nil)
	for _, f := range af {
		_, err := f.Writer(&buf)
		if err != nil {
			m.config.Logger.Errorf("failed to write attachment to memory: %s", err)
			continue
		}
		b, err := m.processBinary(buf.Bytes())
		if err != nil {
			m.config.Logger.Errorf("failed to encrypt attachment: %s", err)
			continue
		}
		if err := msg.AttachReader(f.Name, bytes.NewReader([]byte(b))); err != nil {
			m.config.Logger.Errorf("failed to attach reader: %s", err)
			continue
		}
		buf.Reset()
	}

	return msg
}

// processBinary is a helper function that processes the given data based on the
// configured Action
func (m *Middleware) processBinary(d []byte) (string, error) {
	var ct string
	var err error
	switch m.config.Action {
	case ActionEncrypt:
		ct, err = helper.EncryptBinaryMessageArmored(m.config.PublicKey, d)
	case ActionEncryptAndSign:
		// TODO: Waiting for reply to https://github.com/ProtonMail/gopenpgp/issues/213
		ct, err = helper.EncryptSignMessageArmored(m.config.PublicKey, m.config.PrivKey,
			[]byte(m.config.passphrase), string(d))
	case ActionSign:
		// TODO: Does this work with binary?
		return helper.SignCleartextMessageArmored(m.config.PrivKey, []byte(m.config.passphrase), string(d))
	default:
		return "", ErrUnsupportedAction
	}
	if err != nil {
		return ct, err
	}
	return m.reArmorMessage(ct)
}

// processPlain is a helper function that processes the given data based on the
// configured Action
func (m *Middleware) processPlain(d string) (string, error) {
	var ct string
	var err error
	switch m.config.Action {
	case ActionEncrypt:
		ct, err = helper.EncryptMessageArmored(m.config.PublicKey, d)
	case ActionEncryptAndSign:

		ct, err = helper.EncryptSignMessageArmored(m.config.PublicKey, m.config.PrivKey,
			[]byte(m.config.passphrase), d)
	case ActionSign:
		return helper.SignCleartextMessageArmored(m.config.PrivKey, []byte(m.config.passphrase), d)
	default:
		return "", ErrUnsupportedAction
	}
	if err != nil {
		return ct, err
	}
	return m.reArmorMessage(ct)
}

// reArmorMessage unarmors the PGP message and re-armors it with the package specific
// comment and version strings
func (m *Middleware) reArmorMessage(d string) (string, error) {
	ua, err := armor.Unarmor(d)
	if err != nil {
		return d, err
	}
	return armor.ArmorWithTypeAndCustomHeaders(ua, constants.PGPMessageHeader, armorVersion, armorComment)
}
