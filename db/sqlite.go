package db

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	conn *sql.DB
}

func NewDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite3", path+"?_foreign_keys=1&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS master_key (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            encrypted_check BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );`,
		`CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            notes BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            category_id INTEGER,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
        );`,
		`CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );`,
	}

	for _, query := range queries {
		if _, err := conn.Exec(query); err != nil {
			return nil, fmt.Errorf("failed to create tables: %w", err)
		}
	}

	return &DB{conn: conn}, nil
}

func (db *DB) Close() error {
	if db.conn == nil {
		return nil
	}
	return db.conn.Close()
}

func (db *DB) SaveMasterKey(salt, encryptedCheck []byte) error {
	if len(salt) == 0 || len(encryptedCheck) == 0 {
		return errors.New("invalid key parameters")
	}

	_, err := db.conn.Exec(
		`INSERT OR REPLACE INTO master_key 
		(id, salt, encrypted_check, updated_at) 
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		1, salt, encryptedCheck,
	)
	return err
}

func (db *DB) GetMasterKey() ([]byte, []byte, error) {
	var salt, encryptedCheck []byte
	err := db.conn.QueryRow(
		"SELECT salt, encrypted_check FROM master_key WHERE id = ?", 1,
	).Scan(&salt, &encryptedCheck)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("failed to get master key: %w", err)
	}
	return salt, encryptedCheck, nil
}

func (db *DB) AddEntry(website, username string, encryptedPassword, notes []byte, categoryID *int) error {
	if website == "" || username == "" || len(encryptedPassword) == 0 {
		return errors.New("invalid entry parameters")
	}

	_, err := db.conn.Exec(
		`INSERT INTO passwords 
		(website, username, encrypted_password, notes, category_id) 
		VALUES (?, ?, ?, ?, ?)`,
		website, username, encryptedPassword, notes, categoryID,
	)
	return err
}

func (db *DB) UpdateEntry(id int, website, username string, encryptedPassword, notes []byte, categoryID *int) error {
	_, err := db.conn.Exec(
		`UPDATE passwords SET 
			website = ?, 
			username = ?, 
			encrypted_password = ?, 
			notes = ?, 
			category_id = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		website, username, encryptedPassword, notes, categoryID, id,
	)
	return err
}

func (db *DB) DeleteEntry(id int) error {
	_, err := db.conn.Exec("DELETE FROM passwords WHERE id = ?", id)
	return err
}

func (db *DB) GetAllEntries() ([]PasswordEntry, error) {
	rows, err := db.conn.Query(
		`SELECT id, website, username, encrypted_password, notes, category_id 
		FROM passwords ORDER BY website`)
	if err != nil {
		return nil, fmt.Errorf("failed to query entries: %w", err)
	}
	defer rows.Close()

	var entries []PasswordEntry
	for rows.Next() {
		var entry PasswordEntry
		if err := rows.Scan(
			&entry.ID,
			&entry.Website,
			&entry.Username,
			&entry.EncryptedPassword,
			&entry.Notes,
			&entry.CategoryID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan entry: %w", err)
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return entries, nil
}

type PasswordEntry struct {
	ID                int
	Website           string
	Username          string
	EncryptedPassword []byte
	Notes             []byte
	CategoryID        *int
}

func (db *DB) AddCategory(name string) error {
	if name == "" {
		return errors.New("category name cannot be empty")
	}

	_, err := db.conn.Exec("INSERT INTO categories (name) VALUES (?)", name)
	return err
}

func (db *DB) GetCategories() ([]Category, error) {
	rows, err := db.conn.Query("SELECT id, name FROM categories ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("failed to query categories: %w", err)
	}
	defer rows.Close()

	var categories []Category
	for rows.Next() {
		var c Category
		if err := rows.Scan(&c.ID, &c.Name); err != nil {
			return nil, fmt.Errorf("failed to scan category: %w", err)
		}
		categories = append(categories, c)
	}

	return categories, nil
}

type Category struct {
	ID   int
	Name string
}
