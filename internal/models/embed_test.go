package models

import (
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadModelFromFS_OK(t *testing.T) {
	m, err := LoadModelFromFS("rbac_model.conf")
	require.NoError(t, err)
	require.NotNil(t, m)

	require.IsType(t, model.Model{}, m)

	sections := []string{"r", "p", "e", "m"}

	for _, sec := range sections {
		_, ok := m[sec]
		assert.Truef(t, ok, "section %q should exist", sec)
	}
}

func TestLoadModelFromFS_MissingFile(t *testing.T) {
	m, err := LoadModelFromFS("does_not_exist.conf")
	require.Error(t, err)
	assert.Nil(t, m)
	assert.Contains(t, err.Error(), "error reading model")
}
