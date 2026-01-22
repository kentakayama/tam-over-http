/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package tam

import (
	"bytes"
	"context"
	"crypto"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kentakayama/tam-over-http/internal/domain/model"
	"github.com/kentakayama/tam-over-http/internal/infra/rats"
	"github.com/kentakayama/tam-over-http/internal/infra/sqlite"
	"github.com/kentakayama/tam-over-http/internal/suit"
	"github.com/kentakayama/tam-over-http/resources"
	"github.com/veraison/eat"
	"github.com/veraison/go-cose"
)

type TAM struct {
	verifier    rats.IRAVerifier
	disableCOSE bool           // TODO: remove
	assets      responseAssets // TODO: remove
	logger      *log.Logger
	db          *sql.DB         // Database connection for TAM state
	ctx         context.Context // Background context for database operations
}

type responseAssets struct {
	queryCOSE   []byte
	queryPlain  []byte
	updateCOSE  []byte
	updatePlain []byte
	tamKey      *cose.Key
}

func NewTAM(disableCOSE bool, verifier rats.IRAVerifier, logger *log.Logger) (*TAM, error) {
	var key cose.Key
	err := cbor.Unmarshal(resources.TAMCoseKeyBytes, &key)
	if err != nil {
		return nil, errors.New("failed to load TAM's private key")
	}

	a := responseAssets{
		queryCOSE:   bytes.Clone(resources.QueryRequestCOSE),
		queryPlain:  bytes.Clone(resources.QueryRequestPlain),
		updateCOSE:  bytes.Clone(resources.UpdateCOSE),
		updatePlain: bytes.Clone(resources.UpdatePlain),
		tamKey:      &key,
	}
	if len(a.queryCOSE) == 0 {
		return nil, errors.New("missing embedded query request COSE payload")
	}
	if len(a.updateCOSE) == 0 {
		return nil, errors.New("missing embedded update COSE payload")
	}

	return &TAM{
		verifier:    verifier,
		disableCOSE: disableCOSE,
		assets:      a,
		logger:      logger,
	}, nil
}

func (t *TAM) ResolveTEEPMessage(body []byte) ([]byte, error) {
	var response []byte
	if len(body) == 0 {
		// empty body means session creation, return QueryRequest
		challenge := t.getChallenge()
		if challenge == nil {
			return nil, ErrFatal
		}

		sendingQueryRequest := TEEPMessage{
			Type: TEEPTypeQueryRequest,
			Options: TEEPOptions{
				Challenge: challenge,
			},
			SupportedTEEPCipherSuites: [][]TEEPCipherSuite{
				{
					{
						Type:      cose.CBORTagSign1Message,
						Algorithm: int(cose.AlgorithmESP256),
					},
				},
			},
			SupportedSUITCOSEProfiles: []suit.COSEProfile{
				{
					DigestAlg:      cose.AlgorithmSHA256,
					AuthAlg:        cose.AlgorithmESP256,
					KeyExchangeAlg: cose.Algorithm(-29),
					EncryptionAlg:  cose.Algorithm(-65534),
				},
			},
		}
		response, err := sendingQueryRequest.COSESign1Sign(t.assets.tamKey)
		if err != nil {
			return nil, ErrFatal
		}

		t.saveSentQueryRequest(&sendingQueryRequest, nil)
		return response, nil
	}

	incomingMessage, authenticated, err := t.tryAuthenticateTeepMessage(body)
	if (err != nil && err != ErrNotAuthenticated) || incomingMessage == nil {
		// failed to parse incoming message
		return nil, err
	}

	// TODO: search sent message by myself with token
	sentMessage := t.searchSentMessageWithToken(incomingMessage.Options.Token)
	// NOTE: sentMessage may be nil because the incomingMessage does not contain the token
	// case 1) TAM sent QueryRequest with challenge & request-attestation
	// case 2) someone created malformed TEEP Protocol messages

	switch incomingMessage.Type {
	case TEEPTypeQueryResponse:
		// NOTE: authenticated == false is acceptable, because the verification key might be provided by the Verifier

		if sentMessage == nil {
			// attestation may be requested with challange i.e. the sent message does not contain token
			attestationResults, err := t.verifyAttestationPayload(incomingMessage)
			if err != nil {
				return nil, err
			}

			// if attestationResult status is affirming, extract key from attestiaonPayload
			if !strings.EqualFold(attestationResults.EarStatus, "affirming") {
				return nil, ErrAttestationFailed
			}

			if !authenticated {
				// TODO: extract AttestationResult in EAT form, not Evidence
				s, err := tryCOSESign1OrSign(incomingMessage.Options.AttestationPayload)
				if err != nil {
					return nil, ErrAttestationFailed
				}
				var rawAttestationPayload []byte
				switch m := any(s).(type) {
				case cose.Sign1Message:
					rawAttestationPayload = m.Payload
				case cose.SignMessage:
					rawAttestationPayload = m.Payload
				default:
					return nil, ErrNotSupported
				}

				var eat eat.Eat
				if err := eat.FromCBOR(rawAttestationPayload); err != nil {
					t.logger.Printf("failed to extract attestation public key: %v", err)
					return nil, ErrNotAuthenticated
				}

				// validate that the EAT payload is generated with the challenge the TAM sent
				if err := eat.Nonce.Validate(); err != nil {
					return nil, ErrNotAuthenticated
				}
				if eat.Nonce.Len() != 1 {
					return nil, ErrNotAuthenticated
				}
				sentMessage = t.searchSentMessageWithChallenge(eat.Nonce.GetI(0))
				if sentMessage == nil {
					return nil, ErrNotAuthenticated
				}

				if eat.Cnf == nil || eat.Cnf.Key == nil {
					t.logger.Printf("attestation public key missing in payload")
					return nil, ErrNotAuthenticated
				}
				key := eat.Cnf.Key

				// verify QueryResponse signature
				if err := verifyCOSESignature(body, key); err != nil {
					t.logger.Printf("query-response verification failed: %v", err)
					return nil, ErrNotAuthenticated
				}

				// store the public key for future use
				if err := t.setTEEPAgentKey(key); err != nil {
					t.logger.Printf("failed to store attestation public key: %v", err)
					return nil, ErrFatal
				} else {
					t.logger.Printf("stored attestation public key %v in system keyring.", key)
				}
				authenticated = true
			}
		}

		// finally authenticated?
		if !authenticated || sentMessage == nil {
			return nil, ErrNotAuthenticated
		}

		response, err = t.processQueryResponse(incomingMessage, sentMessage)
		if err != nil {
			return nil, err
		}

	case TEEPTypeSuccess:
		if !authenticated {
			return nil, ErrNotAuthenticated
		}
		t.logger.Printf("do nothing for teep-success")
	case TEEPTypeError:
		if !authenticated {
			return nil, ErrNotAuthenticated
		}
		t.logger.Printf("do nothing for teep-error")
	default:
		// should not reach here, because the corresponding sent message was valid
		return nil, ErrNotSupported
	}

	return response, nil
}

func verifyCOSESignature(raw []byte, pubKey *cose.Key) error {
	alg, err := pubKey.AlgorithmOrDefault()
	if err != nil {
		return fmt.Errorf("verifyCOSESignature: detect algorithm id: %w", err)
	}
	pub, err := pubKey.PublicKey()
	if err != nil {
		return fmt.Errorf("verifyCOSESignature: creating crypto.PublicKey: %w", err)
	}
	verifier, err := cose.NewVerifier(alg, pub)
	if err != nil {
		return fmt.Errorf("verifyCOSESignature: init verifier: %w", err)
	}

	// cose sign1
	var sign1 cose.Sign1Message
	if err := sign1.UnmarshalCBOR(raw); err == nil {
		if err := sign1.Verify(nil, verifier); err != nil {
			return fmt.Errorf("sign1 verification: %w", err)
		}
		return nil
	}
	// cose sign
	var sign cose.SignMessage
	if err := sign.UnmarshalCBOR(raw); err == nil {
		if err := sign.Verify(nil, verifier); err != nil {
			return fmt.Errorf("sign verification: %w", err)
		}
		return nil
	}

	return fmt.Errorf("verifyCOSESignature: unsupported COSE structure")
}

func (t *TAM) tryAuthenticateTeepMessage(raw []byte) (*TEEPMessage, bool, error) {
	s, err := tryCOSESign1OrSign(raw)
	if err != nil {
		return nil, false, err
	}
	message, err := t.checkSignature(s)
	if err != nil {
		t.logger.Print(err)
		return message, false, err
	}
	return message, true, nil
}

func tryCOSESign1OrSign(raw []byte) (any, error) {
	// Try COSE_Sign1
	var sign1 cose.Sign1Message
	if err := sign1.UnmarshalCBOR(raw); err == nil {
		return sign1, nil
	}

	// Try COSE_Sign
	var sign cose.SignMessage
	if err := sign.UnmarshalCBOR(raw); err == nil {
		return sign, nil
	}

	return nil, ErrNotSupported
}

func (t *TAM) checkSignature(msg any) (*TEEPMessage, error) {
	var teepMessage TEEPMessage
	var kid []byte
	switch m := msg.(type) {
	case cose.Sign1Message:
		err := cbor.Unmarshal(m.Payload, &teepMessage)
		if err != nil {
			return nil, ErrNotTEEPMessage
		}
		kid = getKid(m.Headers.Unprotected)
		if kid == nil {
			return &teepMessage, ErrKidIsMissing
		}
	case cose.SignMessage:
		err := cbor.Unmarshal(m.Payload, &teepMessage)
		if err != nil {
			return nil, ErrNotTEEPMessage
		}
		kid = getKid(m.Headers.Unprotected)
		if kid == nil {
			return &teepMessage, ErrKidIsMissing
		}
	default:
		return nil, ErrNotSupported
	}

	key, err := t.getTEEPAgentKey(kid)
	if err != nil {
		return &teepMessage, ErrNotAuthenticated
	}

	publicKey, err := key.PublicKey()
	if err != nil {
		return &teepMessage, ErrFatal
	}
	alg, err := key.AlgorithmOrDefault()
	if err != nil {
		return &teepMessage, ErrFatal
	}
	// create a verifier from a trusted private key
	verifier, err := cose.NewVerifier(alg, publicKey)
	if err != nil {
		return &teepMessage, ErrFatal
	}

	switch m := msg.(type) {
	case cose.Sign1Message:
		err = m.Verify(nil, verifier)
		if err != nil {
			return &teepMessage, ErrNotAuthenticated
		}
	case cose.SignMessage:
		err = m.Verify(nil, verifier)
		if err != nil {
			return &teepMessage, ErrNotAuthenticated
		}
	default:
		return &teepMessage, ErrNotSupported
	}

	return &teepMessage, nil
}

func getKid(u cose.UnprotectedHeader) []byte {
	t := u[int64(4)] // kid
	kid, ok := t.([]byte)
	if !ok || len(kid) == 0 {
		return nil
	}

	return kid
}

func (t *TAM) saveSentQueryRequest(sending *TEEPMessage, agentKID []byte) error {
	if sending == nil {
		return ErrFatal
	}
	if sending.Type != TEEPTypeQueryRequest {
		return ErrFatal
	}

	q := model.SentQueryRequestMessage{
		AgentID:              nil, // TODO, search Agent with KID
		AttestationRequested: sending.attestationRequired(),
		TCListRequested:      sending.tcListRequired(),
	}

	sentQueryRequestRepo := sqlite.NewSentQueryRequestMessageRepository(t.db)
	if sentQueryRequestRepo == nil {
		return ErrFatal
	}

	if sending.Options.Token != nil {
		if _, err := sentQueryRequestRepo.CreateWithToken(t.ctx, sending.Options.Token, &q); err != nil {
			return ErrFatal
		}
	} else if sending.Options.Challenge != nil {
		if _, err := sentQueryRequestRepo.CreateWithChallenge(t.ctx, sending.Options.Challenge, &q); err != nil {
			return ErrFatal
		}
	} else {
		return ErrFatal
	}

	return nil
}

func (t *TAM) getChallenge() []byte {
	challengeRepo := sqlite.NewChallengeRepository(t.db)
	if challengeRepo == nil {
		return nil
	}
	challenge, err := challengeRepo.GenerateUniqueChallenge(t.ctx)
	if err != nil {
		return nil
	}
	return challenge
}

// search sent TEEP message by the TAM itself with challenge
// returns the TEEPMessage, otherwise the error is set
func (t *TAM) searchSentMessageWithChallenge(challenge []byte) *TEEPMessage {
	if challenge == nil {
		return nil
	}

	sentQueryRequestRepo := sqlite.NewSentQueryRequestMessageRepository(t.db)
	if sentQueryRequestRepo == nil {
		return nil
	}
	sentQueryRequest, err := sentQueryRequestRepo.FindByChallenge(t.ctx, challenge)
	if err != nil {
		return nil
	}
	if sentQueryRequest != nil {
		var dataItemRequested uint
		if sentQueryRequest.SentQueryRequestMessage.TCListRequested {
			dataItemRequested += 1
		}
		if sentQueryRequest.SentQueryRequestMessage.AttestationRequested {
			dataItemRequested += 2
		}
		sent := TEEPMessage{
			Type: TEEPTypeQueryRequest,
			Options: TEEPOptions{
				Challenge: challenge,
				// TODO items such as SupportedFreshnessMechanisms, ...
			},
			DataItemRequested: dataItemRequested,
		}
		return &sent
	}

	// nothing found
	return nil
}

// search sent TEEP message by the TAM itself
// returns the TEEPMessage, otherwise the error is set
func (t *TAM) searchSentMessageWithToken(token []byte) *TEEPMessage {
	if token == nil {
		return nil
	}

	sentQueryRequestRepo := sqlite.NewSentQueryRequestMessageRepository(t.db)
	if sentQueryRequestRepo == nil {
		return nil
	}
	sentQueryRequest, err := sentQueryRequestRepo.FindByToken(t.ctx, token)
	if err != nil {
		return nil
	}
	if sentQueryRequest != nil {
		var dataItemRequested uint
		if sentQueryRequest.SentQueryRequestMessage.TCListRequested {
			dataItemRequested += 1
		}
		if sentQueryRequest.SentQueryRequestMessage.AttestationRequested {
			dataItemRequested += 2
		}
		sent := TEEPMessage{
			Type: TEEPTypeQueryRequest,
			Options: TEEPOptions{
				Token: token,
				// TODO items such as SupportedFreshnessMechanisms, ...
			},
			DataItemRequested: dataItemRequested,
		}
		return &sent
	}

	sentUpdateRepo := sqlite.NewSentUpdateMessageRepository(t.db)
	if sentUpdateRepo == nil {
		return nil
	}
	sentUpdate, err := sentUpdateRepo.FindWithManifestsByToken(t.ctx, token)
	if err != nil {
		return nil
	}
	if sentUpdate != nil {
		var manifestList []SUITManifestBstr
		for i := 0; i < len(sentUpdate.Manifests); i++ {
			manifestList = append(manifestList, sentUpdate.Manifests[0].Manifest)
		}
		sent := TEEPMessage{
			Type: TEEPTypeUpdate,
			Options: TEEPOptions{
				Token:        token,
				ManifestList: manifestList,
			},
		}
		return &sent
	}

	// nothing found
	return nil
}

// verifyAttestationPayload extracts the AttestationPayload from the provided TEEPMessage,
// sends it to the Verifier, and returns the resulting ProcessedAttestation.
// If any error occurs during processing, the returned ProcessedAttestation will be nil
// and an appropriate error will be returned.
func (t *TAM) verifyAttestationPayload(incoming *TEEPMessage) (*rats.ProcessedAttestation, error) {
	if incoming.Options.AttestationPayload == nil {
		return nil, ErrAttestationPayloadNotFound
	}

	result, err := t.submitAttestationPayload(incoming.Options.AttestationPayload)
	if err != nil {
		t.logger.Printf("failed to save attestation payload: %v", err)
		return nil, err
	}
	return result, nil
}

func (t *TAM) submitAttestationPayload(data []byte) (*rats.ProcessedAttestation, error) {
	if t.verifier == nil {
		return nil, ErrAttestationFailed
	}

	att, err := t.verifier.Process(data)
	if err != nil {
		t.logger.Printf("challenge-response submission failed: %v", err)
		return nil, ErrAttestationFailed
	}

	return att, nil
}

func (t *TAM) processQueryResponse(incomingMessage *TEEPMessage, sentMessage *TEEPMessage) ([]byte, error) {
	// the incomingMessage (QueryResponse) must be authenticated and the sentMessage must be detected before this function
	if sentMessage == nil {
		return nil, ErrFatal
	}
	if !bytes.Equal(incomingMessage.Options.Token, sentMessage.Options.Token) {
		return nil, ErrFatal
	}

	t.logger.Printf("QueryResponse payload (COSE CBOR):\n%#v", *incomingMessage)

	// TODO: check RequestedTCList

	// TODO: sign on response
	return t.assets.updateCOSE, nil
}

// Init initializes the TAM by setting up database connections and loading/creating default entities.
func (t *TAM) Init() error {
	return t.InitWithPath("tam_state.db")
}

func (t *TAM) InitWithPath(dbPath string) error {
	t.ctx = context.Background()
	// Initialize SQLite database (stored in tam_state.db or even could be :memory:)
	db, err := sqlite.InitDB(t.ctx, dbPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	t.db = db

	return nil
}

func (t *TAM) EnsureDefaultTCDeveloper() error {
	// XXX: initialize default entiries only for demo purpose

	// Try to find or create "default" TC Developer
	devRepo := sqlite.NewTCDeveloperRepository(t.db)

	// add default developer if not exists
	defaultDev := &model.TCDeveloper{
		Name:      "default",
		CreatedAt: time.Now().UTC(),
	}

	var devID int64
	dev, err := devRepo.FindByName(t.ctx, defaultDev.Name)
	if err != nil {
		return fmt.Errorf("failed to find default TC Developer: %w", err)
	}
	if dev != nil {
		devID = dev.ID
		// OK, already exists
	} else {
		devID, err = devRepo.Create(t.ctx, defaultDev)
		if err != nil {
			return fmt.Errorf("failed to create default TC Developer: %w", err)
		}
		t.logger.Printf("Created default TC Developer with ID: %d", devID)
	}

	// add default developer key if not exists
	key := cose.Key{
		Type:      cose.KeyTypeEC2,
		Algorithm: cose.AlgorithmESP256,
		Params: map[any]any{
			cose.KeyLabelEC2Curve: cose.CurveP256,
			cose.KeyLabelEC2X: []byte{
				0x84, 0x96, 0x81, 0x1A, 0xAE, 0x0B, 0xAA, 0xAB,
				0xD2, 0x61, 0x57, 0x18, 0x9E, 0xEC, 0xDA, 0x26,
				0xBE, 0xAA, 0x8B, 0xF1, 0x1B, 0x6F, 0x3F, 0xE6,
				0xE2, 0xB5, 0x65, 0x9C, 0x85, 0xDB, 0xC0, 0xAD,
			},
			cose.KeyLabelEC2Y: []byte{
				0x3B, 0x1F, 0x2A, 0x4B, 0x6C, 0x09, 0x81, 0x31,
				0xC0, 0xA3, 0x6D, 0xAC, 0xD1, 0xD7, 0x8B, 0xD3,
				0x81, 0xDC, 0xDF, 0xB0, 0x9C, 0x05, 0x2D, 0xB3,
				0x39, 0x91, 0xDB, 0x73, 0x38, 0xB4, 0xA8, 0x96,
			},
		},
	}
	kid, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil
	}
	encodedKey, err := cbor.Marshal(key)
	if err != nil {
		return nil
	}

	defaultDevKey := &model.ManifestSigningKey{
		KID:           kid,
		TCDeveloperID: devID,
		PublicKey:     encodedKey,
	}
	keyRepo := sqlite.NewManifestSigningKeyRepository(t.db)

	k, err := keyRepo.FindByKID(t.ctx, kid)
	if err != nil {
		return fmt.Errorf("failed to find default TC Developer: %w", err)
	}
	if k != nil {
		// OK, already exists
	} else {
		devKeyID, err := keyRepo.Create(t.ctx, defaultDevKey)
		if err != nil {
			return fmt.Errorf("failed to create default TC Developer: %w", err)
		}
		t.logger.Printf("Created default TC Developer with ID: %d", devKeyID)
	}
	return nil
}

func (t *TAM) EnsureDefaultTEEPAgent() error {
	// XXX: initialize default entiries only for demo purpose

	// add default TEEP Agent's key if not exists
	fixedES256AgentKey := []byte{
		0xA5,       //# map(5)
		0x01,       //# unsigned(1) / 1 = kty /
		0x02,       //# unsigned(2) / 2 = EC2 /
		0x03,       //# unsigned(3) / 3 = alg /
		0x26,       //# negative(6) / -7 = ES256 /
		0x20,       //# negative(0) / -1 = crv /
		0x01,       //# unsigned(1) / 1 = P-256 /
		0x21,       //# negative(1) / -2 = x /
		0x58, 0x20, //# bytes(32)
		0x58, 0x86, 0xcd, 0x61, 0xdd, 0x87, 0x58, 0x62,
		0xe5, 0xaa, 0xa8, 0x20, 0xe7, 0xa1, 0x52, 0x74,
		0xc9, 0x68, 0xa9, 0xbc, 0x96, 0x04, 0x8d, 0xdc,
		0xac, 0xe3, 0x2f, 0x50, 0xc3, 0x65, 0x1b, 0xa3,
		0x22,       //# negative(2) / -3 = y /
		0x58, 0x20, //# bytes(32)
		0x9e, 0xed, 0x81, 0x25, 0xe9, 0x32, 0xcd, 0x60,
		0xc0, 0xea, 0xd3, 0x65, 0x0d, 0x0a, 0x48, 0x5c,
		0xf7, 0x26, 0xd3, 0x78, 0xd1, 0xb0, 0x16, 0xed,
		0x42, 0x98, 0xb2, 0x96, 0x1e, 0x25, 0x8f, 0x1b,
	}
	var keyES256 cose.Key
	err := cbor.Unmarshal(fixedES256AgentKey, &keyES256)
	if err != nil {
		return errors.New("failed to initialize fixed TEEP Agent's key")
	}
	kidES256, _ := keyES256.Thumbprint(crypto.SHA256)
	t.logger.Printf("ES256 Key = {x: %s, y: %s, kid: %s}",
		hex.EncodeToString(keyES256.Params[cose.KeyLabelEC2X].([]byte)),
		hex.EncodeToString(keyES256.Params[cose.KeyLabelEC2Y].([]byte)),
		hex.EncodeToString(kidES256))
	agentES256, _ := t.getTEEPAgentKey(kidES256)
	if agentES256 != nil {
		// OK, already exists
	} else {
		err = t.setTEEPAgentKey(&keyES256)
		if err != nil {
			// log the error but do not fail initialization
			t.logger.Printf("Failed to store ES256 default TEEP Agent's key: %v", err)
		} else {
			t.logger.Printf("Stored default ES256 TEEP Agent's key %v in system keyring.", &keyES256)
		}
	}

	fixedESP256AgentKey := []byte{
		0xA5,       //# map(5)
		0x01,       //# unsigned(1) / 1 = kty /
		0x02,       //# unsigned(2) / 2 = EC2 /
		0x03,       //# unsigned(3) / 3 = alg /
		0x28,       //# negative(8) / -9 = ESP256 /
		0x20,       //# negative(0) / -1 = crv /
		0x01,       //# unsigned(1) / 1 = P-256 /
		0x21,       //# negative(1) / -2 = x /
		0x58, 0x20, //# bytes(32)
		0xBE, 0x7C, 0x56, 0x99, 0x3F, 0x71, 0x11, 0x45,
		0x34, 0xC2, 0xF4, 0xA4, 0xF4, 0xE4, 0x60, 0x67,
		0x84, 0xFA, 0x9D, 0x96, 0x35, 0xE1, 0x22, 0xBC,
		0x8A, 0x49, 0x0B, 0x2E, 0x11, 0xFE, 0xB9, 0x32,
		0x22,       //# negative(2) / -3 = y /
		0x58, 0x20, //# bytes(32)
		0x81, 0x69, 0x6B, 0x42, 0xC3, 0xBE, 0x1B, 0x24,
		0x4C, 0xC0, 0x3B, 0xCA, 0x97, 0xF0, 0xCE, 0x75,
		0xE2, 0xD9, 0x3A, 0xDA, 0x1C, 0xE5, 0x56, 0x62,
		0x92, 0x27, 0xF1, 0x0A, 0x8C, 0x2C, 0x5B, 0x29,
	}
	var keyESP256 cose.Key
	err = cbor.Unmarshal(fixedESP256AgentKey, &keyESP256)
	if err != nil {
		return errors.New("failed to initialize fixed TEEP Agent's key")
	}
	kidESP256, _ := keyESP256.Thumbprint(crypto.SHA256)
	t.logger.Printf("ESP256 Key = {x: %s, y: %s, kid: %s}",
		hex.EncodeToString(keyESP256.Params[cose.KeyLabelEC2X].([]byte)),
		hex.EncodeToString(keyESP256.Params[cose.KeyLabelEC2Y].([]byte)),
		hex.EncodeToString(kidESP256))
	agentESP256, _ := t.getTEEPAgentKey(kidESP256)
	if agentESP256 != nil {
		// OK, already exists
	} else {
		err = t.setTEEPAgentKey(&keyESP256)
		if err != nil {
			// log the error but do not fail initialization
			t.logger.Printf("Failed to store default ESP256 TEEP Agent's key: %v", err)
		} else {
			t.logger.Printf("Stored default ESP256 TEEP Agent's key %v in system keyring.", &keyESP256)
		}
	}

	return nil
}

// Close closes the database connection.
func (t *TAM) Close() error {
	if t.db != nil {
		return sqlite.CloseDB(t.db)
	}
	return nil
}
