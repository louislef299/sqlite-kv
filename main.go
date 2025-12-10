package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	kvs := map[string]string{
		"louis": "lefebvre",
		"henry": "lefebvre",
		"elise": "higgins",
	}

	db, err := sql.Open("sqlite3", "./kv.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createKeyTable(db)

	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}

	stmt, err := tx.Prepare("INSERT INTO kv(key, value) values(?, ?)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	for k, v := range kvs {
		_, err = stmt.Exec(k, v)
		if err != nil {
			log.Fatal(err)
		}
	}

	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
	}
}

func createKeyTable(db *sql.DB) {
	_, err := db.Exec(`CREATE TABLE kv 
	(key integer not null primary key, value text);`)
	if err != nil {
		log.Fatal(err)
	}
}
