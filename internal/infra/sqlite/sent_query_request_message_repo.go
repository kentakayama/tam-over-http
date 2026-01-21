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

// SentQueryRequestMessageRepository handles sent query request message persistence.
type SentQueryRequestMessageRepository struct {
	db *sql.DB
}

func NewSentQueryRequestMessageRepository(db *sql.DB) *SentQueryRequestMessageRepository {
	return &SentQueryRequestMessageRepository{db: db}
}

// Create inserts a new sent query request message and returns the inserted id.
func (r *SentQueryRequestMessageRepository) Create(ctx context.Context, msg *model.SentQueryRequestMessage) (int64, error) {
	const q = `
		INSERT INTO sent_query_request_messages (agent_id, attestation_requested, tc_list_requested, token_id, challenge_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	res, err := r.db.ExecContext(ctx, q, msg.AgentID, msg.AttestationRequested, msg.TCListRequested, msg.TokenID, msg.ChallengeID, msg.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("insert sent query request message: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// FindByTokenID returns sent query request messages by token_id.
func (r *SentQueryRequestMessageRepository) FindByTokenID(ctx context.Context, tokenID int64) (*model.SentQueryRequestMessage, error) {
	const q = `
		SELECT id, agent_id, attestation_requested, tc_list_requested, token_id, challenge_id, created_at
		FROM sent_query_request_messages
		WHERE token_id = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, tokenID)
	var msg model.SentQueryRequestMessage
	if err := row.Scan(&msg.ID, &msg.AgentID, &msg.AttestationRequested, &msg.TCListRequested, &msg.TokenID, &msg.ChallengeID, &msg.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan sent query request message: %w", err)
	}
	return &msg, nil
}

// FindByChallengeID returns sent query request messages by challenge_id.
func (r *SentQueryRequestMessageRepository) FindByChallengeID(ctx context.Context, challengeID int64) (*model.SentQueryRequestMessage, error) {
	const q = `
		SELECT id, agent_id, attestation_requested, tc_list_requested, token_id, challenge_id, created_at
		FROM sent_query_request_messages
		WHERE challenge_id = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, challengeID)
	var msg model.SentQueryRequestMessage
	if err := row.Scan(&msg.ID, &msg.AgentID, &msg.AttestationRequested, &msg.TCListRequested, &msg.TokenID, &msg.ChallengeID, &msg.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan sent query request message: %w", err)
	}
	return &msg, nil
}

// FindByID returns a sent query request message by ID. Basically not used.
func (r *SentQueryRequestMessageRepository) FindByID(ctx context.Context, id int64) (*model.SentQueryRequestMessage, error) {
	const q = `
		SELECT id, agent_id, attestation_requested, tc_list_requested, token_id, challenge_id, created_at
		FROM sent_query_request_messages
		WHERE id = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, id)
	var msg model.SentQueryRequestMessage
	if err := row.Scan(&msg.ID, &msg.AgentID, &msg.AttestationRequested, &msg.TCListRequested, &msg.TokenID, &msg.ChallengeID, &msg.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan sent query request message: %w", err)
	}
	return &msg, nil
}
