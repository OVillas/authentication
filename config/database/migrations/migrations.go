package main

import (
	"log"

	"github.com/OVillas/autentication/config"
	"github.com/OVillas/autentication/config/database"
	"github.com/OVillas/autentication/models"
)

func main() {
	config.Load()

	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Fatal(err)
	}

	err = db.AutoMigrate(
		&models.User{},
	)

	if err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	log.Println("Migrations executed successfully.")
}
