/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/kentakayama/tam-over-http/internal/domain"
	"github.com/kentakayama/tam-over-http/internal/domain/model"
)

type AgentRepository struct {
	db *sql.DB
}

// NewAgentRepository creates a new instance of AgentRepository.
func NewAgentRepository(db *sql.DB) *AgentRepository {
	return &AgentRepository{db: db}
}

func (r *AgentRepository) FindByKID(ctx context.Context, kid []byte) (*model.Agent, error) {
	const query = `
		SELECT id, kid, created_at, expired_at, revoked_at, public_key
		FROM agents
		WHERE kid = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, kid)
	var a model.Agent
	var revokedAtUnix sql.NullInt64
	if err := row.Scan(&a.ID, &a.KID, &a.CreatedAt, &a.ExpiredAt, &revokedAtUnix, &a.PublicKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	// Convert Unix timestamp to *time.Time
	if revokedAtUnix.Valid {
		t := time.Unix(revokedAtUnix.Int64, 0).UTC()
		a.RevokedAt = &t
	}

	// Check if revoked
	if a.RevokedAt != nil {
		return nil, domain.ErrRevoked
	}

	now := time.Now()
	if a.ExpiredAt.Before(now) {
		return nil, domain.ErrExpired
	}

	return &a, nil
}

// FindByKIDIgnoreRevoked finds an agent by KID without checking revoked status.
// It only checks if the agent exists and is not expired.
func (r *AgentRepository) FindByKIDIgnoreRevoked(ctx context.Context, kid []byte) (*model.Agent, error) {
	const query = `
		SELECT id, kid, created_at, expired_at, revoked_at, public_key
		FROM agents
		WHERE kid = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, kid)
	var a model.Agent
	var revokedAtUnix sql.NullInt64
	if err := row.Scan(&a.ID, &a.KID, &a.CreatedAt, &a.ExpiredAt, &revokedAtUnix, &a.PublicKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	// Convert Unix timestamp to *time.Time
	if revokedAtUnix.Valid {
		t := time.Unix(revokedAtUnix.Int64, 0).UTC()
		a.RevokedAt = &t
	}

	now := time.Now()
	if a.ExpiredAt.Before(now) {
		return nil, domain.ErrExpired
	}

	return &a, nil
}

func (r *AgentRepository) Create(ctx context.Context, a *model.Agent) error {
	const query = `
		INSERT INTO agents (kid, created_at, expired_at, revoked_at, public_key)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query, a.KID, a.CreatedAt, a.ExpiredAt, a.RevokedAt, a.PublicKey)
	return err
}

// RevokeByKID marks an agent as revoked by setting revoked_at to the current Unix timestamp.
func (r *AgentRepository) RevokeByKID(ctx context.Context, kid []byte) error {
	const query = `
		UPDATE agents
		SET revoked_at = ?
		WHERE kid = ? AND revoked_at IS NULL
	`
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, query, now.Unix(), kid)
	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return domain.ErrNotFound
	}

	return nil
}
