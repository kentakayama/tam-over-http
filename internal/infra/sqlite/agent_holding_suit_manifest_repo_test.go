/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/kentakayama/tam-over-http/internal/domain/model"
)

func TestAgentHolding_AddForAgent_And_ListActive(t *testing.T) {
	ctx := context.Background()
	db, err := InitDB(ctx, ":memory:")
	if err != nil {
		t.Fatalf("InitDB error: %v", err)
	}
	defer CloseDB(db)

	// create an agent directly and get its ID
	now := time.Now().UTC().Truncate(time.Second)
	res, err := db.ExecContext(ctx, "INSERT INTO agents (kid, public_key, created_at, expired_at) VALUES (?, ?, ?, ?)", []byte("agent-1"), []byte("pk"), now, now.Add(1*time.Hour))
	if err != nil {
		t.Fatalf("insert agent error: %v", err)
	}
	agentID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("lastinsertid agent error: %v", err)
	}

	// Create TC Developer
	entityRepo := NewEntityRepository(db)
	dev := &model.Entity{Name: "Test Corp", IsTCDeveloper: true, CreatedAt: now}
	devID, err := entityRepo.Create(ctx, dev)
	if err != nil {
		t.Fatalf("Create developer error: %v", err)
	}

	// Create manifest signing key
	keyRepo := NewManifestSigningKeyRepository(db)
	key := &model.ManifestSigningKey{
		KID:       []byte("key-1"),
		EntityID:  devID,
		PublicKey: []byte("pub-key-1"),
		CreatedAt: now,
		ExpiredAt: now.Add(1 * time.Hour),
	}
	keyID, err := keyRepo.Create(ctx, key)
	if err != nil {
		t.Fatalf("Create key error: %v", err)
	}

	// create two manifests with same trusted_component_id
	manifestRepo := NewSuitManifestRepository(db)
	trusted := []byte("tc-99")
	m1 := &model.SuitManifest{Manifest: []byte("m1"), ManifestSigningKeyID: keyID, TrustedComponentID: trusted, SequenceNumber: 1, CreatedAt: now}
	m2 := &model.SuitManifest{Manifest: []byte("m2"), ManifestSigningKeyID: keyID, TrustedComponentID: trusted, SequenceNumber: 2, CreatedAt: now.Add(1 * time.Minute)}

	id1, err := manifestRepo.Create(ctx, m1)
	if err != nil {
		t.Fatalf("create m1: %v", err)
	}
	id2, err := manifestRepo.Create(ctx, m2)
	if err != nil {
		t.Fatalf("create m2: %v", err)
	}

	hrepo := NewAgentHoldingSuitManifestRepository(db)

	// add first manifest
	if err := hrepo.AddForAgent(ctx, agentID, id1); err != nil {
		t.Fatalf("AddForAgent m1 error: %v", err)
	}

	list, err := hrepo.ListActiveByAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("ListActiveByAgent error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 active holding, got %d", len(list))
	}
	if list[0].SuitManifestID != id1 {
		t.Fatalf("expected suit manifest id %d got %d", id1, list[0].SuitManifestID)
	}

	// add second manifest (same trusted component) -> first should be logically deleted
	if err := hrepo.AddForAgent(ctx, agentID, id2); err != nil {
		t.Fatalf("AddForAgent m2 error: %v", err)
	}

	list2, err := hrepo.ListActiveByAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("ListActiveByAgent after m2 error: %v", err)
	}
	if len(list2) != 1 {
		t.Fatalf("expected 1 active holding after replacement, got %d", len(list2))
	}
	if list2[0].SuitManifestID != id2 {
		t.Fatalf("expected suit manifest id %d got %d", id2, list2[0].SuitManifestID)
	}
}
