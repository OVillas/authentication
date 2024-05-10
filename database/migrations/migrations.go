package main

import (
	"log"

	"github.com/OVillas/autentication/config"
	"github.com/OVillas/autentication/config/database"
	"github.com/OVillas/autentication/domain"
)

func main() {
	config.Load()

	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Fatal(err)
	}

	err = db.AutoMigrate(
		&domain.User{},
	)

	if err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	log.Println("Migrations executed successfully.")
}
