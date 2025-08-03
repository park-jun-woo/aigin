// pkg/auth/GroupModel.go
package auth

import (
	"context"
	"database/sql"
	"log"
)

type GroupModel struct {
	DB *sql.DB
}

func NewGroupModel(db *sql.DB) *GroupModel {
	return &GroupModel{
		DB: db,
	}
}

func (m *GroupModel) Exists(ctx context.Context, targetTable string, category string) (bool, error) {
	var exists bool
	err := m.DB.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM groups WHERE target_table = $1 AND id = $2)", targetTable, category).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (m *GroupModel) GetGroups(ctx context.Context, targetTable string) (*AllGroups, error) {
	query := "SELECT id, name FROM groups WHERE target_table=$1"
	rows, err := m.DB.QueryContext(ctx, query, targetTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := []GroupsItem{}
	for rows.Next() {
		var group GroupsItem
		if err := rows.Scan(
			&group.ID,
			&group.Name,
		); err != nil {
			log.Printf("scan error: %v", err)
			continue
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &AllGroups{
		Items: groups,
	}, nil
}
