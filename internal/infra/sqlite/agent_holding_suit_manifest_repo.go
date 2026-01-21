/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/kentakayama/tam-over-http/internal/domain/model"
)

// AgentHoldingSuitManifestRepository handles agent -> manifest holdings.
type AgentHoldingSuitManifestRepository struct {
	db *sql.DB
}

func NewAgentHoldingSuitManifestRepository(db *sql.DB) *AgentHoldingSuitManifestRepository {
	return &AgentHoldingSuitManifestRepository{db: db}
}

// AddForAgent logically deletes existing holdings for the same trusted_component and inserts a new holding.
// This operation is performed in a transaction to ensure atomicity.
func (r *AgentHoldingSuitManifestRepository) AddForAgent(ctx context.Context, agentID int64, suitManifestID int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Find trusted_component_id for the suit_manifest being added
	var trustedComponentID []byte
	if err := tx.QueryRowContext(ctx, "SELECT trusted_component_id FROM suit_manifests WHERE id = ?", suitManifestID).Scan(&trustedComponentID); err != nil {
		return fmt.Errorf("lookup trusted_component_id: %w", err)
	}

	// Mark existing active holdings for this agent and trusted_component as deleted
	upd := `
		UPDATE agent_holding_suit_manifests
		SET deleted = 1
		WHERE agent_id = ?
		  AND deleted = 0
		  AND suit_manifest_id IN (
			SELECT id FROM suit_manifests WHERE trusted_component_id = ?
		  )
	`
	if _, err := tx.ExecContext(ctx, upd, agentID, trustedComponentID); err != nil {
		return fmt.Errorf("mark deleted: %w", err)
	}

	// Insert the new holding
	ins := `
		INSERT INTO agent_holding_suit_manifests (agent_id, suit_manifest_id, created_at, deleted)
		VALUES (?, ?, CURRENT_TIMESTAMP, 0)
	`
	if _, err := tx.ExecContext(ctx, ins, agentID, suitManifestID); err != nil {
		return fmt.Errorf("insert holding: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ListActiveByAgent returns active holdings for an agent.
func (r *AgentHoldingSuitManifestRepository) ListActiveByAgent(ctx context.Context, agentID int64) ([]*model.AgentHoldingSuitManifest, error) {
	const q = `
		SELECT id, agent_id, suit_manifest_id, deleted, created_at
		FROM agent_holding_suit_manifests
		WHERE agent_id = ? AND deleted = 0
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, q, agentID)
	if err != nil {
		return nil, fmt.Errorf("query holdings: %w", err)
	}
	defer rows.Close()

	var out []*model.AgentHoldingSuitManifest
	for rows.Next() {
		var h model.AgentHoldingSuitManifest
		if err := rows.Scan(&h.ID, &h.AgentID, &h.SuitManifestID, &h.Deleted, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan holding: %w", err)
		}
		out = append(out, &h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows err: %w", err)
	}
	return out, nil
}
