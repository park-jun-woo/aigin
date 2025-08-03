// pkg/auth/UserModel.go
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lib/pq"
)

type UserModel struct {
	DB *sql.DB
}

func NewUserModel(db *sql.DB) *UserModel {
	return &UserModel{
		DB: db,
	}
}

func (m *UserModel) AllUsers(ctx context.Context) (*AllUsers, error) {
	query := `SELECT id, name, email, email_verified, status, created_at, updated_at, deleted_at, groups
		FROM view_users`
	rows, err := m.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UsersItem
	for rows.Next() {
		var user UsersItem
		if err := rows.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.EmailVerified,
			&user.Status,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.DeletedAt,
			pq.Array(&user.Groups),
		); err != nil {
			log.Printf("scan error: %v", err)
			continue
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &AllUsers{Items: users}, nil
}

func (m *UserModel) GetUsers(
	ctx context.Context, limit int, page int, order string, desc string, search string, group string,
) (*UsersResult, error) {
	offset := (page - 1) * limit

	where := []string{}
	whereCount := 0
	options := []string{}
	arguments := []interface{}{}
	argumentIndex := 1

	if search != "" {
		where = append(where,
			fmt.Sprintf("(id ILIKE $%d OR name ILIKE $%d OR email ILIKE $%d)",
				argumentIndex, argumentIndex+1, argumentIndex+2))
		arguments = append(arguments, "%"+search+"%", "%"+search+"%", "%"+search+"%")
		argumentIndex += 3
		whereCount += 3
	}

	if group != "" {
		where = append(where,
			fmt.Sprintf("group = $%d", argumentIndex))
		arguments = append(arguments, group)
		argumentIndex++
		whereCount++
	}

	options = append(options, fmt.Sprintf("LIMIT $%d OFFSET $%d", argumentIndex, argumentIndex+1))
	arguments = append(arguments, limit, offset)
	argumentIndex += 2

	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}

	optionClause := ""
	if len(options) > 0 {
		optionClause = " " + strings.Join(options, " ")
	}

	query := fmt.Sprintf(`SELECT
		id, name, email, email_verified, status, created_at, updated_at, deleted_at, groups
		FROM view_users%s ORDER BY %s %s %s`, whereClause, order, desc, optionClause)
	rows, err := m.DB.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []UsersItem{}
	for rows.Next() {
		var user UsersItem
		if err := rows.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.EmailVerified,
			&user.Status,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.DeletedAt,
			&user.Groups,
		); err != nil {
			log.Printf("scan error: %v", err)
			continue
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var total int
	totalQuery := fmt.Sprintf("SELECT count(*) FROM users%s", whereClause)
	if err := m.DB.QueryRowContext(ctx, totalQuery, arguments[:whereCount]...).Scan(&total); err != nil {
		return nil, err
	}

	return &UsersResult{
		Items:   users,
		Total:   total,
		Limit:   limit,
		Page:    page,
		Order:   order,
		Desc:    desc,
		HasNext: total > (page * limit),
	}, nil

}

func (m *UserModel) GetUser(ctx context.Context, id string) (*UsersItem, error) {
	query := `SELECT
		id, name, email, emailverified, status, created_at, updated_at, deleted_at, groups
		FROM view_users WHERE id = $1`
	row := m.DB.QueryRowContext(ctx, query, id)

	var user UsersItem
	if err := row.Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.EmailVerified,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
		&user.Groups,
	); err != nil {
		return nil, err
	}

	return &user, nil
}

func (m *UserModel) PostUser(
	ctx context.Context, id string, name string, email string, email_verified string,
	status string, created_at *time.Time, updated_at *time.Time, deleted_at *time.Time,
	actor_id string, actor_name string,
) (string, error) {
	// 사용자 등록
	const query = `INSERT INTO users (id, name, email, email_verified, status, created_at, updated_at, deleted_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`
	_, err := m.DB.ExecContext(
		ctx, query,
		id, name, email, email_verified, status, created_at, updated_at, deleted_at,
	)
	if err != nil {
		return "", err
	}
	// 로그 생성날짜
	createdAt := time.Now().UTC()
	// 로그 등록
	logQuery := `INSERT INTO logs (target_table, target_row, action_id, actor_id, actor_name, created_at)
		VALUES ('users', $1, 'CREATED', $2, $3, $4);`
	m.DB.ExecContext(ctx, logQuery, id, actor_id, actor_name, createdAt)

	return id, nil
}

func (m *UserModel) PutUser(
	ctx context.Context, id string, name string, email string, email_verified string,
	status string, updated_at *time.Time,
	actor_id string, actor_name string,
) (bool, error) {
	// 사용자 수정
	query := `UPDATE users SET name=$1,email=$2,email_verified=$3,status=$4,updated_at=$5
		WHERE id=$6`
	res, err := m.DB.ExecContext(ctx, query, name, email, email_verified, status, updated_at, id)
	if err != nil {
		return false, err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if rowsAffected == 0 {
		return false, fmt.Errorf("no rows affected")
	}
	// 로그 생성성일자
	createdAt := time.Now().UTC()
	// 로그 등록
	const logQuery = `INSERT INTO logs (target_table, target_row, action_id, actor_id, actor_name, created_at)
		VALUES ('users', $1, 'UPDATED', $2, $3, $4)`
	m.DB.ExecContext(ctx, logQuery, id, actor_id, actor_name, createdAt)
	// 결과 반환
	return true, nil
}

func (m *UserModel) DeleteUser(ctx context.Context, id string, actor_id string, actor_name string) (bool, error) {
	// 로그 생성성일자
	createdAt := time.Now().UTC()
	// 사용자 수정
	query := `UPDATE users SET status='DELETED',deleted_at=$1
		WHERE id=$2`
	res, err := m.DB.ExecContext(ctx, query, createdAt, id)
	if err != nil {
		return false, err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if rowsAffected == 0 {
		return false, fmt.Errorf("no rows affected")
	}
	// 로그 등록
	const logQuery = `INSERT INTO logs (target_table, target_row, action_id, actor_id, actor_name, created_at)
		VALUES ('users', $1, 'DELETED', $2, $3, $4)`
	m.DB.ExecContext(ctx, logQuery, id, actor_id, actor_name, createdAt)
	// 결과 반환
	return true, nil
}

// SyncGroup 는 user_groups 를 id 한 사용자에 대해 groups 값과 동기화한다.
// actorID / actorName은 감사 로그 등에 사용할 수 있도록 받지만,
// 예시에서는 동기화 로직만 구현.
func (m *UserModel) SyncGroup(
	ctx context.Context, userID string, groups []string,
	actorID string, actorName string,
) (bool, error) {

	if userID == "" {
		return false, errors.New("userID is empty")
	}
	// 트랜잭션 시작
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	// 1) 현재 DB에 저장된 그룹 목록 가져오기
	rows, err := tx.QueryContext(
		ctx,
		`SELECT group_id FROM user_groups WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	currentSet := make(map[string]struct{})
	for rows.Next() {
		var gid string
		if err = rows.Scan(&gid); err != nil {
			return false, err
		}
		currentSet[gid] = struct{}{}
	}
	if err = rows.Err(); err != nil {
		return false, err
	}
	// 2) 원하는 그룹 목록을 집합으로 변환
	targetSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		targetSet[g] = struct{}{}
	}
	// 3) 차집합 계산
	var toInsert []string // DB에 없고 targetSet 에 있는 것
	var toDelete []string // DB에는 있는데 targetSet 에 없는 것

	for g := range targetSet {
		if _, exists := currentSet[g]; !exists {
			toInsert = append(toInsert, g)
		}
	}
	for g := range currentSet {
		if _, keep := targetSet[g]; !keep {
			toDelete = append(toDelete, g)
		}
	}
	// 4) INSERT
	for _, g := range toInsert {
		if _, err = tx.ExecContext(
			ctx,
			`INSERT INTO user_groups (user_id, group_id)
			 VALUES ($1, $2)
			 ON CONFLICT DO NOTHING`,
			userID, g,
		); err != nil {
			return false, err
		}
		// 필요하다면 logs 테이블 등에 AUDIT 기록 가능
	}
	// 5) DELETE
	if len(toDelete) > 0 {
		if _, err = tx.ExecContext(
			ctx,
			`DELETE FROM user_groups
			  WHERE user_id = $1
			    AND group_id = ANY($2)`,
			userID,
			pq.Array(toDelete),
		); err != nil {
			return false, err
		}
	}
	// 6) 커밋
	if err = tx.Commit(); err != nil {
		return false, err
	}

	changed := len(toInsert) > 0 || len(toDelete) > 0
	return changed, nil
}
