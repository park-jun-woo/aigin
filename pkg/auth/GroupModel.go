// internal/auth/GroupModel.go
package auth

import (
	"context"
	"database/sql"
)

type GroupModel struct {
	DB *sql.DB
}

func NewGroupModel(db *sql.DB) *GroupModel {
	return &GroupModel{
		DB: db,
	}
}

func (m *GroupModel) Exists(ctx context.Context, group string) (bool, error) {
	var exists bool
	err := m.DB.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1)", group).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}
