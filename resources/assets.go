/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

package resources

import (
	_ "embed"
)

var (
	//go:embed tam_priv.cbor
	TAMCoseKeyBytes []byte

	//go:embed query_request.tam.es256.cose
	QueryRequestCOSE []byte

	//go:embed query_request.cbor
	QueryRequestPlain []byte

	//go:embed update.tam.es256.cose
	UpdateCOSE []byte

	//go:embed update.cbor
	UpdatePlain []byte
)
