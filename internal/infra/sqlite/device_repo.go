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

	"github.com/kentakayama/tam-over-http/internal/domain"
	"github.com/kentakayama/tam-over-http/internal/domain/model"
)

type DeviceRepository struct {
	db *sql.DB
}

// NewDeviceRepository creates a new instance of DeviceRepository.
func NewDeviceRepository(db *sql.DB) *DeviceRepository {
	return &DeviceRepository{db: db}
}

func (r *DeviceRepository) FindByUEID(ctx context.Context, ueid []byte) (*model.Device, error) {
	const query = `
		SELECT ueid
		FROM devices
		WHERE ueid = ?
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, ueid)
	var d model.Device
	if err := row.Scan(&d.UEID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	return &d, nil
}

func (r *DeviceRepository) Create(ctx context.Context, d *model.Device) error {
	const query = `
		INSERT INTO devices (ueid)
		VALUES (?)
	`
	_, err := r.db.ExecContext(ctx, query, d.UEID)
	return err
}
