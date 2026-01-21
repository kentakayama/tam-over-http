/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package model

import "time"

// SuitManifest represents a SUIT manifest stored in DB.
type SuitManifest struct {
	ID                   int64
	Manifest             []byte
	ManifestSigningKeyID int64
	TrustedComponentID   []byte
	SequenceNumber       uint64
	CreatedAt            time.Time
}
