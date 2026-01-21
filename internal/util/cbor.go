package util

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/fxamacker/cbor/v2"
)

func RenderCBORPretty(decoded any) (string, error) {
	normalised, err := normaliseCBORForJSON(decoded)
	if err != nil {
		return "", err
	}

	pretty, err := json.MarshalIndent(normalised, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty), nil
}

func normaliseCBORForJSON(value any) (any, error) {
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for i, elem := range v {
			norm, err := normaliseCBORForJSON(elem)
			if err != nil {
				return nil, err
			}
			out[i] = norm
		}
		return out, nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		out := make(map[string]any, len(v))
		for _, k := range keys {
			norm, err := normaliseCBORForJSON(v[k])
			if err != nil {
				return nil, err
			}
			out[k] = norm
		}
		return out, nil
	case map[any]any:
		type entry struct {
			key string
			val any
		}

		entries := make([]entry, 0, len(v))
		for key, val := range v {
			keyStr := stringifyCBORKey(key)
			norm, err := normaliseCBORForJSON(val)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry{key: keyStr, val: norm})
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].key < entries[j].key
		})

		out := make(map[string]any, len(entries))
		for _, e := range entries {
			out[e.key] = e.val
		}
		return out, nil
	case []byte:
		return fmt.Sprintf("h'%x'", v), nil
	case cbor.Tag:
		content, err := normaliseCBORForJSON(v.Content)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"_cborTag": v.Number,
			"content":  content,
		}, nil
	default:
		return v, nil
	}
}

func stringifyCBORKey(key any) string {
	switch k := key.(type) {
	case string:
		return k
	case fmt.Stringer:
		return k.String()
	case []byte:
		return fmt.Sprintf("h'%x'", k)
	default:
		return fmt.Sprint(k)
	}
}
