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

// TokenRepository handles token persistence.
type TokenRepository struct {
	db *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// Create inserts a new token and returns the inserted id.
func (r *TokenRepository) Create(ctx context.Context, t *model.Token) (int64, error) {
	const q = `
		INSERT INTO tokens (token, created_at, expired_at, consumed)
		VALUES (?, ?, ?, ?)
	`
	res, err := r.db.ExecContext(ctx, q, t.Token, t.CreatedAt, t.ExpiredAt, t.Consumed)
	if err != nil {
		return 0, fmt.Errorf("insert token: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// FindByToken returns a token by its token bytes.
func (r *TokenRepository) FindByToken(ctx context.Context, tokenBytes []byte) (*model.Token, error) {
	const q = `
		SELECT id, token, created_at, expired_at, consumed
		FROM tokens
		WHERE token = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, tokenBytes)
	var t model.Token
	if err := row.Scan(&t.ID, &t.Token, &t.CreatedAt, &t.ExpiredAt, &t.Consumed); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan token: %w", err)
	}
	return &t, nil
}

// MarkConsumed marks a token as consumed.
func (r *TokenRepository) MarkConsumed(ctx context.Context, id int64) error {
	const q = `
		UPDATE tokens
		SET consumed = 1
		WHERE id = ?
	`
	_, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("update token: %w", err)
	}
	return nil
}

// FindByID returns a token by its ID. Basically not used.
func (r *TokenRepository) FindByID(ctx context.Context, id int64) (*model.Token, error) {
	const q = `
		SELECT id, token, created_at, expired_at, consumed
		FROM tokens
		WHERE id = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, id)
	var t model.Token
	if err := row.Scan(&t.ID, &t.Token, &t.CreatedAt, &t.ExpiredAt, &t.Consumed); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan token: %w", err)
	}
	return &t, nil
}
