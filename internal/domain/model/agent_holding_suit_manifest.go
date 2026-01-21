/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package model

import "time"

// AgentHoldingSuitManifest represents an agent's possession of a SUIT manifest.
type AgentHoldingSuitManifest struct {
	ID             int64
	AgentID        int64
	SuitManifestID int64
	Deleted        bool
	CreatedAt      time.Time
}
