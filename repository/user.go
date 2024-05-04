package repository

import (
	"errors"
	"log/slog"
	"time"

	"github.com/OVillas/autentication/config/database"
	"github.com/OVillas/autentication/models"
	"gorm.io/gorm"
)

type userRepository struct{}

func NewUserRepository() models.UserRepository {
	return userRepository{}
}

func (ur userRepository) Create(user models.User) error {
	log := slog.With(
		slog.String("func", "Create"),
		slog.String("repository", "user"))

	log.Info("Create repository initiated")

	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error connecting to the database", err)
		return err
	}

	now := time.Now()

	user.CreatedAt = now
	user.UpdateAt = now

	result := db.Create(&user)

	if result.Error != nil {
		log.Error("Error to create user in database", result.Error)
		return result.Error
	}

	log.Info("create repository executed successfully")
	return nil
}

func (ur userRepository) GetAll() ([]models.User, error) {
	log := slog.With(
		slog.String("func", "GetAll"),
		slog.String("repository", "user"))

	log.Info("GetAll repository initiated")
	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error connecting to the database", err)
		return nil, err
	}
	var users []models.User

	result := db.Find(&users)

	err = result.Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error("Error: ", err)
		return nil, err
	}

	log.Info("get all repository executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return users, nil
}

func (ur userRepository) GetById(id string) (*models.User, error) {
	log := slog.With(
		slog.String("func", "GetById"),
		slog.String("repository", "user"))

	log.Info("GetById repository initiated")

	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error connecting to the database", err)
		return nil, err
	}

	var user models.User
	err = db.Where("id = ?", id).First(&user).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	log.Info("get by id service executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

func (ur userRepository) GetByUsername(username string) (*models.User, error) {
	log := slog.With(
		slog.String("func", "GetByNick"),
		slog.String("repository", "user"))
	
	log.Info("GetByNick repository initiated")

	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error connecting to the database", err)
		return nil, err
	}

	var user models.User
	err = db.Where("email = ? OR nick = ?", username, username).First(&user).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error("Error: ", err)
		return nil, err
	}

	log.Info("get by username repository executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

func (ur userRepository) GetByNameOrNick(nameOrNick string) ([]models.User, error) {
	log := slog.With(
		slog.String("func", "GetByName"),
		slog.String("repository", "user"))

	log.Info("GetByName repository initiated")

	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error connecting to the database", err)
		return nil, err
	}

	var users []models.User
	searchPattern := "%" + nameOrNick + "%"
	err = db.Where("name LIKE ? OR nick LIKE ?", searchPattern, searchPattern).Find(&users).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error("Error: ", err)
		return nil, err
	}

	log.Info("get by name repository executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return users, nil
}

func (ur userRepository) GetByEmail(email string) (*models.User, error) {
	log := slog.With(
		slog.String("func", "GetByEmail"),
		slog.String("repository", "user"))

	log.Info("GetByEmail repository initiated")

	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error connecting to the database", err)
		return nil, err
	}

	var user models.User
	err = db.Where("email = ?", email).First(&user).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error("Error: ", err)
		return nil, err
	}

	log.Info("get by email repository executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

func (ur userRepository) Update(id string, user models.User) error {
	log := slog.With(
		slog.String("func", "Create"),
		slog.String("repository", "user"))
	log.Info("Update repository initiated")
	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error connecting to the database", err)
		return err
	}

	err = db.Model(&models.User{}).Where("id = ?", id).Updates(models.User{Name: user.Name, Email: user.Email}).Error
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("update repository executed successfully")
	return nil
}

func (ur userRepository) Delete(id string) error {
	log := slog.With(
		slog.String("func", "Delete"),
		slog.String("repository", "user"))

	log.Info("Delete repository initiated")

	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error: ", err)
		return err
	}
	err = db.Delete(&models.User{}, "id = ?", id).Error
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("delete repository executed successfully")
	return nil
}

func (ur userRepository) UpdatePassword(id string, password string) error {
	log := slog.With(
		slog.String("func", "updatePassword"),
		slog.String("repository", "user"))

	log.Info("UpdatePassword repository initiated")

	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error connecting to the database", err)
		return err
	}

	err = db.Model(&models.User{}).Where("id = ?", id).Updates(models.User{Password: password}).Error
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("update password repository executed successfully")
	return nil
}

func (ur userRepository) ConfirmedEmail(id string) error {
	log := slog.With(
		slog.String("func", "UpdateConfirmedEmail"),
		slog.String("repository", "user"))
	
	log.Info("UpdateConfirmedEmail repository initiated")
	
	db, err := database.NewMysqlConnection()
	if err != nil {
		log.Error("Error connecting to the database", err)
		return err
	}

	err = db.Model(&models.User{}).Where("id = ?", id).Updates(models.User{EmailConfirmed: true}).Error
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("update confirmed email repository executed successfully")
	return nil
}
