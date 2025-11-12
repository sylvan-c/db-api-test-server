package db

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/lib/pq"
)

type DBAdapter interface {
	Begin() (*sql.Tx, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

func Connect(dsn string) (*sql.DB, error) {
	var db *sql.DB
	var err error

	for i := 0; i < 10; i++ {
		db, err = sql.Open("postgres", dsn)
		if err != nil {
			log.Printf("DB connection failed: %v", err)
		} else {
			err = db.Ping()
			if err == nil {
				log.Println("Connected to DB")
				return db, nil
			}
			log.Printf("DB ping failed: %v", err)
		}

		log.Println("Retrying in 2s...")
		time.Sleep(2 * time.Second)
	}

	log.Fatalf("Could not connect to DB after retries: %v", err)
	return nil, err
}
