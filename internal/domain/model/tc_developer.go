/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package model

import "time"

// TCDeveloper represents a Trusted Component Developer.
type TCDeveloper struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}
