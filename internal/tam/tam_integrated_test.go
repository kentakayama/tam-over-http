//go:build integration

/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package tam

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/kentakayama/tam-over-http/internal/config"
	"github.com/kentakayama/tam-over-http/internal/infra/rats"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTAMResolveTEEPMessage_VERAISON_PSA_OK(t *testing.T) {
	logger := log.Default()
	verifierClient, err := rats.NewVerifierClient(config.RAConfig{
		BaseURL:     "https://localhost:8443/",
		ContentType: `application/psa-attestation-token`,
		InsecureTLS: true,
		Timeout:     60 * time.Second,
		Logger:      logger,
	})
	require.Nil(t, err)
	tam, err := NewTAM(false, verifierClient, logger)
	if err != nil {
		t.Fatalf("NewTAM error: %v", err)
	}
	if err = tam.Init(); err != nil {
		t.Fatalf("TAM Init error: %v", err)
	}
	if err = tam.EnsureDefaultEntity(); err != nil {
		t.Fatalf("TAM EnsureDefaultEntity error: %v", err)
	}
	if err = tam.EnsureDefaultTEEPAgent(); err != nil {
		t.Fatalf("TAM EnsureDefaultTEEPAgent error: %v", err)
	}

	kid, err := tam.assets.tamKey.Thumbprint(crypto.SHA256)
	fmt.Printf("TAM's kid: %s\n", hex.EncodeToString(kid))
	require.Nil(t, err)
	require.NotNil(t, kid)

	// TEST#1: return QueryRequest against empty body
	response, err := tam.ResolveTEEPMessage(nil)
	require.Nil(t, err)

	outgoingMessage, authenticated, err := tam.tryAuthenticateTeepMessage(response)
	// correct, because its TAM's message, whose key is not in the key chain
	require.Equal(t, ErrNotAuthenticated, err)
	require.Equal(t, false, authenticated)

	require.NotNil(t, outgoingMessage)
	require.Equal(t, TEEPTypeQueryRequest, outgoingMessage.Type)

	// TEST#2: return Update against QueryResponse
	response, err = tam.ResolveTEEPMessage(queryResponsePSAESP256)
	require.Nil(t, err)

	outgoingMessage, authenticated, err = tam.tryAuthenticateTeepMessage(response)
	// correct, because its TAM's message, whose key is not in the key chain
	require.Equal(t, ErrNotAuthenticated, err)
	require.Equal(t, false, authenticated)

	require.NotNil(t, outgoingMessage)
	require.Equal(t, TEEPTypeUpdate, outgoingMessage.Type)
}

func TestTAMResolveTEEPMessage_VERAISON_EAT_OK(t *testing.T) {
	logger := log.Default()
	verifierClient, err := rats.NewVerifierClient(config.RAConfig{
		BaseURL:     "https://localhost:8443/",
		ContentType: `application/eat-cwt; profile="urn:ietf:rfc:rfc9711"`,
		InsecureTLS: true,
		Timeout:     60 * time.Second,
		Logger:      logger,
	})
	require.Nil(t, err)
	tam, err := NewTAM(false, verifierClient, logger)
	if err != nil {
		t.Fatalf("NewTAM error: %v", err)
	}
	if err = tam.Init(); err != nil {
		t.Fatalf("TAM Init error: %v", err)
	}
	if err = tam.EnsureDefaultEntity(); err != nil {
		t.Fatalf("TAM EnsureDefaultEntity error: %v", err)
	}
	if err = tam.EnsureDefaultTEEPAgent(); err != nil {
		t.Fatalf("TAM EnsureDefaultTEEPAgent error: %v", err)
	}

	kid, err := tam.assets.tamKey.Thumbprint(crypto.SHA256)
	fmt.Printf("TAM's kid: %s\n", hex.EncodeToString(kid))
	require.Nil(t, err)
	require.NotNil(t, kid)

	// TEST#1: return QueryRequest against empty body
	response, err := tam.ResolveTEEPMessage(nil)
	require.Nil(t, err)

	outgoingMessage, authenticated, err := tam.tryAuthenticateTeepMessage(response)
	// correct, because its TAM's message, whose key is not in the key chain
	require.Equal(t, ErrNotAuthenticated, err)
	require.Equal(t, false, authenticated)

	require.NotNil(t, outgoingMessage)
	require.Equal(t, TEEPTypeQueryRequest, outgoingMessage.Type)

	// TEST#2: return Update against QueryResponse
	response, err = tam.ResolveTEEPMessage(queryResponseEATESP256)
	assert.Nil(t, err)

	outgoingMessage, authenticated, err = tam.tryAuthenticateTeepMessage(response)
	// correct, because its TAM's message, whose key is not in the key chain
	require.Equal(t, ErrNotAuthenticated, err)
	require.Equal(t, false, authenticated)

	require.NotNil(t, outgoingMessage)
	require.Equal(t, TEEPTypeUpdate, outgoingMessage.Type)
}
