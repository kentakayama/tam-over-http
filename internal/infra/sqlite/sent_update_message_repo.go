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

// SentUpdateMessageWithManifests represents a sent update message with its associated SUIT manifests and token.
type SentUpdateMessageWithManifests struct {
	SentUpdateMessage model.SentUpdateMessage
	Token             model.Token
	Manifests         []model.SuitManifest
}

// SentUpdateMessageRepository handles sent update message persistence.
type SentUpdateMessageRepository struct {
	db *sql.DB
}

func NewSentUpdateMessageRepository(db *sql.DB) *SentUpdateMessageRepository {
	return &SentUpdateMessageRepository{db: db}
}

// Create inserts a new sent update message and returns the inserted id.
func (r *SentUpdateMessageRepository) Create(ctx context.Context, msg *model.SentUpdateMessage) (int64, error) {
	const q = `
		INSERT INTO sent_update_messages (agent_id, token_id, created_at)
		VALUES (?, ?, ?)
	`
	res, err := r.db.ExecContext(ctx, q, msg.AgentID, msg.TokenID, msg.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("insert sent update message: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// FindByTokenID returns sent update messages by token_id.
func (r *SentUpdateMessageRepository) FindByTokenID(ctx context.Context, tokenID int64) (*model.SentUpdateMessage, error) {
	const q = `
		SELECT id, agent_id, token_id, created_at
		FROM sent_update_messages
		WHERE token_id = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, tokenID)
	var msg model.SentUpdateMessage
	if err := row.Scan(&msg.ID, &msg.AgentID, &msg.TokenID, &msg.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan sent update message: %w", err)
	}
	return &msg, nil
}

// FindByID returns a sent update message by ID. Basically not used.
func (r *SentUpdateMessageRepository) FindByID(ctx context.Context, id int64) (*model.SentUpdateMessage, error) {
	const q = `
		SELECT id, agent_id, token_id, created_at
		FROM sent_update_messages
		WHERE id = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, id)
	var msg model.SentUpdateMessage
	if err := row.Scan(&msg.ID, &msg.AgentID, &msg.TokenID, &msg.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan sent update message: %w", err)
	}
	return &msg, nil
}

// FindWithManifestsByToken returns a sent update message with its associated SUIT manifests by token.
func (r *SentUpdateMessageRepository) FindWithManifestsByToken(ctx context.Context, token []byte) (*SentUpdateMessageWithManifests, error) {
	const q = `
		SELECT t.id, t.token, t.created_at, t.expired_at, t.consumed,
		       sum.id, sum.agent_id, sum.token_id, sum.created_at,
		       sm.id, sm.manifest, sm.manifest_signing_key_id, sm.trusted_component_id, sm.sequence_number, sm.created_at
		FROM tokens t
		JOIN sent_update_messages sum ON t.id = sum.token_id
		LEFT JOIN sent_manifests_in_update_messages smium ON sum.id = smium.sent_update_id
		LEFT JOIN suit_manifests sm ON smium.suit_manifest_id = sm.id
		WHERE t.token = ?
	`
	rows, err := r.db.QueryContext(ctx, q, token)
	if err != nil {
		return nil, fmt.Errorf("query sent update message with manifests: %w", err)
	}
	defer rows.Close()

	var result *SentUpdateMessageWithManifests
	for rows.Next() {
		var tok model.Token
		var msg model.SentUpdateMessage
		var manifestID sql.NullInt64
		var manifestData sql.NullString
		var manifestSigningKeyID sql.NullInt64
		var trustedComponentID sql.NullString
		var sequenceNumber sql.NullInt64
		var manifestCreatedAt sql.NullTime

		err := rows.Scan(
			&tok.ID, &tok.Token, &tok.CreatedAt, &tok.ExpiredAt, &tok.Consumed,
			&msg.ID, &msg.AgentID, &msg.TokenID, &msg.CreatedAt,
			&manifestID, &manifestData, &manifestSigningKeyID, &trustedComponentID, &sequenceNumber, &manifestCreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		if result == nil {
			result = &SentUpdateMessageWithManifests{
				SentUpdateMessage: msg,
				Token:             tok,
				Manifests:         []model.SuitManifest{},
			}
		}

		if manifestID.Valid {
			manifest := model.SuitManifest{
				ID:                   manifestID.Int64,
				Manifest:             []byte(manifestData.String),
				ManifestSigningKeyID: manifestSigningKeyID.Int64,
				TrustedComponentID:   []byte(trustedComponentID.String),
				SequenceNumber:       uint64(sequenceNumber.Int64),
				CreatedAt:            manifestCreatedAt.Time,
			}
			result.Manifests = append(result.Manifests, manifest)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	if result == nil {
		return nil, nil // No rows found
	}

	return result, nil
}
