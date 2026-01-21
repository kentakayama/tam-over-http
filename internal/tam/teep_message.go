/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package tam

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kentakayama/tam-over-http/internal/suit"
)

// draft-ietf-teep-protocol

type TEEPMessage struct {
	_       struct{}        `cbor:",toarray"`
	Type    TEEPMessageType `cbor:"0,keyasint"`
	Options TEEPOptions     `cbor:"1,keyasint"`

	// for QueryRequest
	SupportedTEEPCipherSuites [][]TEEPCipherSuite
	SupportedSUITCOSEProfiles []suit.COSEProfile
	DataItemRequested         uint

	// for Error
	ErrCode TEEPErrCode
}

func (m TEEPMessage) MarshalCBOR() ([]byte, error) {
	switch m.Type {
	case TEEPTypeQueryRequest:
		return cbor.Marshal([]any{m.Type, m.Options, m.SupportedTEEPCipherSuites, m.SupportedSUITCOSEProfiles, m.DataItemRequested})
	case TEEPTypeQueryResponse:
		return cbor.Marshal([]any{m.Type, m.Options})
	case TEEPTypeUpdate:
		return cbor.Marshal([]any{m.Type, m.Options})
	case TEEPTypeSuccess:
		return cbor.Marshal([]any{m.Type, m.Options})
	case TEEPTypeError:
		return cbor.Marshal([]any{m.Type, m.Options, m.ErrCode})
	default:
		return nil, ErrNotSupported
	}
}

func (m *TEEPMessage) UnmarshalCBOR(data []byte) error {
	var a []cbor.RawMessage
	err := cbor.Unmarshal(data, &a)
	if err != nil {
		return err
	}
	if len(a) < 2 {
		return ErrNotTEEPMessage
	}
	err = cbor.Unmarshal(a[0], &m.Type)
	if err != nil {
		return err
	}

	switch m.Type {
	case TEEPTypeQueryRequest:
		if len(a) != 5 {
			return ErrInvalidValue
		}
		err = cbor.Unmarshal(a[1], &m.Options)
		if err != nil {
			return err
		}
		err = cbor.Unmarshal(a[2], &m.SupportedTEEPCipherSuites)
		if err != nil {
			return err
		}
		err = cbor.Unmarshal(a[3], &m.SupportedSUITCOSEProfiles)
		if err != nil {
			return err
		}
		err = cbor.Unmarshal(a[4], &m.DataItemRequested)
		if err != nil {
			return err
		}
	case TEEPTypeQueryResponse, TEEPTypeUpdate, TEEPTypeSuccess:
		if len(a) != 2 {
			return ErrInvalidValue
		}
		err = cbor.Unmarshal(a[1], &m.Options)
		if err != nil {
			return err
		}
	case TEEPTypeError:
		if len(a) != 3 {
			return ErrInvalidValue
		}
		err = cbor.Unmarshal(a[1], &m.Options)
		if err != nil {
			return err
		}
		err = cbor.Unmarshal(a[2], &m.ErrCode)
		if err != nil {
			return err
		}
	default:
		return ErrNotSupported
	}

	return nil
}

type TEEPMessageType int

const (
	TEEPTypeUnknown       TEEPMessageType = 0
	TEEPTypeQueryRequest  TEEPMessageType = 1
	TEEPTypeQueryResponse TEEPMessageType = 2
	TEEPTypeUpdate        TEEPMessageType = 3
	TEEPTypeSuccess       TEEPMessageType = 5
	TEEPTypeError         TEEPMessageType = 6
)

func (t TEEPMessageType) String() string {
	switch t {
	case TEEPTypeQueryRequest:
		return "query-request"
	case TEEPTypeQueryResponse:
		return "query-response"
	case TEEPTypeUpdate:
		return "update"
	case TEEPTypeSuccess:
		return "teep-success"
	case TEEPTypeError:
		return "teep-error"
	default:
		return fmt.Sprintf("unknown(%d)", int(t))
	}
}

func (t *TEEPMessage) attestationRequired() bool {
	if t.Type == TEEPTypeQueryRequest && (t.DataItemRequested&0b1 != 0) {
		return true
	}
	return false
}

func (t *TEEPMessage) tcListRequired() bool {
	if t.Type == TEEPTypeQueryRequest && (t.DataItemRequested&0b10 != 0) {
		return true
	}
	return false
}

func (t *TEEPMessage) extListRequired() bool {
	if t.Type == TEEPTypeQueryRequest && (t.DataItemRequested&0b100 != 0) {
		return true
	}
	return false
}

func (t *TEEPMessage) suitReportsRequired() bool {
	if t.Type == TEEPTypeQueryRequest && (t.DataItemRequested&0b1000 != 0) {
		return true
	}
	return false
}

type TEEPOptions struct {
	SupportedTEEPCipherSuites    [][]TEEPCipherSuite         `cbor:"1,keyasint,omitempty"`
	Challenge                    []byte                      `cbor:"2,keyasint,omitempty"`
	Versions                     []TEEPVersion               `cbor:"3,keyasint,omitempty"`
	SupportedSUITCOSEProfiles    []suit.COSEProfile          `cbor:"4,keyasint,omitempty"`
	SelectedVersion              *TEEPVersion                `cbor:"6,keyasint,omitempty"`
	AttestationPayload           []byte                      `cbor:"7,keyasint,omitempty"`
	TCList                       []suit.SystemPropertyClaims `cbor:"8,keyasint,omitempty"`
	ExtList                      []TEEPExtInfo               `cbor:"9,keyasint,omitempty"`
	ManifestList                 []SUITManifestBstr          `cbor:"10,keyasint,omitempty"`
	Msg                          *string                     `cbor:"11,keyasint,omitempty"`
	ErrMsg                       *string                     `cbor:"12,keyasint,omitempty"`
	AttestationPayloadFormat     *string                     `cbor:"13,keyasint,omitempty"`
	RequestedTCList              []RequestedTCInfo           `cbor:"14,keyasint,omitempty"`
	UnneededManifestList         []SUITManifestBstr          `cbor:"15,keyasint,omitempty"`
	SUITReports                  []suit.Report               `cbor:"19,keyasint,omitempty"`
	Token                        []byte                      `cbor:"20,keyasint,omitempty"`
	SupportedFreshnessMechanisms []FreshnessMechanism        `cbor:"21,keyasint,omitempty"`
	ErrCode                      TEEPErrCode                 `cbor:"23,keyasint,omitempty"`
}

type TEEPVersion uint32
type TEEPExtInfo uint32

type TEEPErrCode uint8

const (
	TEEPErrPermanentError                 = 1
	TEEPErrUnsupportedExtension           = 2
	TEEPErrUnsupportedFreshnessMechanisms = 3
	TEEPErrUnsupportedMsgVersion          = 4
	TEEPErrUnsupportedCipherSuites        = 5
	TEEPErrBadCertificate                 = 6
	TEEPErrAttestationRequired            = 7
	TEEPErrUnsupportedSUITReport          = 8
	TEEPErrCertificateExpired             = 9
	TEEPErrTemporaryError                 = 10
	TEEPErrManifestProcessingFailed       = 17
)

func (e TEEPErrCode) String() string {
	switch e {
	case TEEPErrPermanentError:
		return "ERR_PERMANENT_ERROR"
	case TEEPErrUnsupportedExtension:
		return "ERR_UNSUPPORTED_EXTENSION"
	case TEEPErrUnsupportedFreshnessMechanisms:
		return "ERR_UNSUPPORTED_FRESHNESS_MECHANISMS"
	case TEEPErrUnsupportedMsgVersion:
		return "ERR_UNSUPPORTED_MSG_VERSION"
	case TEEPErrUnsupportedCipherSuites:
		return "ERR_UNSUPPORTED_CIPHER_SUITES"
	case TEEPErrBadCertificate:
		return "ERR_BAD_CERTIFICATE"
	case TEEPErrAttestationRequired:
		return "ERR_ATTESTATION_REQUIRED"
	case TEEPErrUnsupportedSUITReport:
		return "ERR_UNSUPPORTED_SUIT_REPORT"
	case TEEPErrCertificateExpired:
		return "ERR_CERTIFICATE_EXPIRED"
	case TEEPErrTemporaryError:
		return "ERR_TEMPORARY_ERROR"
	case TEEPErrManifestProcessingFailed:
		return "ERR_MANIFEST_PROCESSING_FAILED"
	default:
		return fmt.Sprintf("unknown(%d)", int(e))
	}
}

type TEEPCipherSuite struct {
	_         struct{} `cbor:",toarray"`
	Type      int      `cbor:"0,keyasint"`
	Algorithm int      `cbor:"1,keyasint"`
}

type RequestedTCInfo struct {
	ComponentID              suit.ComponentID `cbor:"16,keyasint,omitempty"`
	TCManifestSequenceNumber uint8            `cbor:"17,keyasint,omitempty"`
	HaveBinary               bool             `cbor:"18,keyasint,omitempty"`
}

type FreshnessMechanism uint

type SUITManifestBstr []byte
