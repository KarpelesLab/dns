package main

import (
	"log"

	"github.com/boltdb/bolt"
)

var db *bolt.DB

func initDb() error {
	var err error

	dbFile := []string{
		"/etc/go-dnsd.db",
		"go-dnsd.db",
	}

	for _, f := range dbFile {
		db, err = bolt.Open(f, 0600, nil)
		if err == nil {
			log.Printf("[db] opened database file %s", f)
			return nil
		}
	}
	return err
}
