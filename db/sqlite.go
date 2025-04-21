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

	// Enable foreign key support
	if _, err := conn.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Create tables with improved schema
	queries := []string{
		`CREATE TABLE IF NOT EXISTS master_key (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			salt BLOB NOT NULL,
			hashed_key BLOB NOT NULL,
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
			FOREIGN KEY (id) REFERENCES categories(id) ON DELETE SET NULL
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

func (db *DB) SaveMasterKey(salt, hashedKey []byte) error {
	if len(salt) == 0 || len(hashedKey) == 0 {
		return errors.New("invalid key parameters")
	}

	_, err := db.conn.Exec(
		`INSERT OR REPLACE INTO master_key 
		(id, salt, hashed_key, updated_at) 
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		1, salt, hashedKey,
	)
	return err
}

func (db *DB) GetMasterKey() ([]byte, []byte, error) {
	var salt, hashedKey []byte
	err := db.conn.QueryRow(
		"SELECT salt, hashed_key FROM master_key WHERE id = ?", 1,
	).Scan(&salt, &hashedKey)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("failed to get master key: %w", err)
	}
	return salt, hashedKey, nil
}

func (db *DB) AddEntry(website, username, encryptedPassword, notes []byte, categoryID *int) error {
	if len(website) == 0 || len(username) == 0 || len(encryptedPassword) == 0 {
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
	Website           []byte
	Username          []byte
	EncryptedPassword []byte
	Notes             []byte
	CategoryID        *int
}

func (db *DB) AddCategory(name string) error {
	if len(name) == 0 {
		return errors.New("category name cannot be empty")
	}

	_, err := db.conn.Exec("INSERT INTO categories (name) VALUES (?)", name)
	return err
}

func (db *DB) GetCategories() ([]Category, error) {
	rows, err := db.conn.Query("SELECT id, name FROM categories ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []Category
	for rows.Next() {
		var c Category
		if err := rows.Scan(&c.ID, &c.Name); err != nil {
			return nil, err
		}
		categories = append(categories, c)
	}

	return categories, nil
}

type Category struct {
	ID   int
	Name string
}
