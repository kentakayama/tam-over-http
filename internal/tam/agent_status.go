/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package tam

import (
	"fmt"

	"github.com/kentakayama/tam-over-http/internal/domain/model"
	"github.com/kentakayama/tam-over-http/internal/infra/sqlite"
)

// to be returned in /dev-admin/getAgents
type AgentStatusList []AgentStatus

type AgentStatus struct {
	TrustedComponentID []byte

	Attributes AgentAttributes            `cbor:"attributes"`
	Manifests  model.SuitManifestOverview `cbor:"wapp_list"`
}

type AgentAttributes struct {
	UEID []byte `cbor:"256,keyasint"`
}

func (t *TAM) getAgentStatus(entityID int64) ([]AgentStatus, error) {
	entityRepo := sqlite.NewEntityRepository(t.db)
	entity, err := entityRepo.FindByID(t.ctx, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to search entity key ID: %v", err)
	}
}
