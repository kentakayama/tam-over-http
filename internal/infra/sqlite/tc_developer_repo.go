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

// TCDeveloperRepository handles Trusted Component Developer persistence.
type TCDeveloperRepository struct {
	db *sql.DB
}

func NewTCDeveloperRepository(db *sql.DB) *TCDeveloperRepository {
	return &TCDeveloperRepository{db: db}
}

// Create inserts a new TC Developer and returns the inserted id.
func (r *TCDeveloperRepository) Create(ctx context.Context, dev *model.TCDeveloper) (int64, error) {
	const q = `
		INSERT INTO tc_developers (name, created_at)
		VALUES (?, ?)
	`
	res, err := r.db.ExecContext(ctx, q, dev.Name, dev.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("insert tc_developer: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// FindByID returns a TC Developer by ID. Basically not used.
func (r *TCDeveloperRepository) FindByID(ctx context.Context, id int64) (*model.TCDeveloper, error) {
	const q = `
		SELECT id, name, created_at
		FROM tc_developers
		WHERE id = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, id)
	var dev model.TCDeveloper
	if err := row.Scan(&dev.ID, &dev.Name, &dev.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan tc_developer: %w", err)
	}
	return &dev, nil
}

// FindByName returns a TC Developer by name.
func (r *TCDeveloperRepository) FindByName(ctx context.Context, name string) (*model.TCDeveloper, error) {
	const q = `
		SELECT id, name, created_at
		FROM tc_developers
		WHERE name = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, q, name)
	var dev model.TCDeveloper
	if err := row.Scan(&dev.ID, &dev.Name, &dev.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan tc_developer: %w", err)
	}
	return &dev, nil
}
