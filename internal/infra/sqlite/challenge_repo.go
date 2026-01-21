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

// ChallengeRepository handles challenge persistence.
type ChallengeRepository struct {
	db *sql.DB
}

func NewChallengeRepository(db *sql.DB) *ChallengeRepository {
	return &ChallengeRepository{db: db}
}

// Create inserts a new challenge and returns the inserted id.
func (r *ChallengeRepository) Create(ctx context.Context, c *model.Challenge) (int64, error) {
	const q = `
		INSERT INTO challenges (challenge, created_at, expired_at, consumed)
		VALUES (?, ?, ?, ?)
	`
	res, err := r.db.ExecContext(ctx, q, c.Challenge, c.CreatedAt, c.ExpiredAt, c.Consumed)
	if err != nil {
		return 0, fmt.Errorf("insert challenge: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// FindByChallenge returns a challenge by its challenge bytes.
func (r *ChallengeRepository) FindByChallenge(ctx context.Context, challengeBytes []byte) (*model.Challenge, error) {
	const q = `
		SELECT id, challenge, created_at, expired_at, consumed
		FROM challenges
		WHERE challenge = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, challengeBytes)
	var c model.Challenge
	if err := row.Scan(&c.ID, &c.Challenge, &c.CreatedAt, &c.ExpiredAt, &c.Consumed); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan challenge: %w", err)
	}
	return &c, nil
}

// MarkConsumed marks a challenge as consumed.
func (r *ChallengeRepository) MarkConsumed(ctx context.Context, id int64) error {
	const q = `
		UPDATE challenges
		SET consumed = 1
		WHERE id = ?
	`
	_, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("update challenge: %w", err)
	}
	return nil
}

// FindByID returns a challenge by its ID. Basically not used.
func (r *ChallengeRepository) FindByID(ctx context.Context, id int64) (*model.Challenge, error) {
	const q = `
		SELECT id, challenge, created_at, expired_at, consumed
		FROM challenges
		WHERE id = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, id)
	var c model.Challenge
	if err := row.Scan(&c.ID, &c.Challenge, &c.CreatedAt, &c.ExpiredAt, &c.Consumed); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan challenge: %w", err)
	}
	return &c, nil
}
