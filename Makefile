.PHONY: run

run:
	@go run main.go

migration:
	go run config/database/migrations/migrations.go