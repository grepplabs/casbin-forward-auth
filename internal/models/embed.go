package models

import (
	"embed"
	"fmt"

	"github.com/casbin/casbin/v2/model"
)

//go:embed *.conf
var FS embed.FS

func LoadModelFromFS(name string) (model.Model, error) {
	data, err := FS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("error reading model %s: %w", name, err)
	}
	m, err := model.NewModelFromString(string(data))
	if err != nil {
		return nil, fmt.Errorf("error parsing model %s: %w", name, err)
	}
	return m, nil
}
