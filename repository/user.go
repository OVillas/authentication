package repository

import (
	"errors"
	"log/slog"
	"time"

	"github.com/OVillas/autentication/domain"
	"github.com/samber/do"
	"gorm.io/gorm"
)

type userRepository struct {
	i  *do.Injector
	db *gorm.DB
}

func NewUserRepository(i *do.Injector) (domain.UserRepository, error) {
	db := do.MustInvoke[*gorm.DB](i)
	return &userRepository{
		db: db,
		i:  i,
	}, nil
}

func (ur *userRepository) Create(user domain.User) error {
	log := slog.With(
		slog.String("func", "Create"),
		slog.String("repository", "user"))

	log.Info("Create initiated")

	now := time.Now()
	user.CreatedAt = now
	user.UpdateAt = now

	result := ur.db.Create(&user)

	if result.Error != nil {
		log.Error("Error to create user in database", result.Error)
		return result.Error
	}

	log.Info("create executed successfully")
	return nil
}

func (ur *userRepository) GetAll() ([]domain.User, error) {
	log := slog.With(
		slog.String("func", "GetAll"),
		slog.String("repository", "user"))

	log.Info("GetAll initiated")

	var users []domain.User

	result := ur.db.Find(&users)

	err := result.Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error("Error: ", err)
		return nil, err
	}

	log.Info("GetAll executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return users, nil
}

func (ur *userRepository) GetById(id string) (*domain.User, error) {
	log := slog.With(
		slog.String("func", "GetById"),
		slog.String("repository", "user"))

	log.Info("GetById initiated")

	var user domain.User
	err := ur.db.Where("id = ?", id).First(&user).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	log.Info("getById executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

func (ur *userRepository) GetByUsername(username string) (*domain.User, error) {
	log := slog.With(
		slog.String("func", "GetByUsername"),
		slog.String("repository", "user"))

	log.Info("GetByUsername initiated")

	var user domain.User
	err := ur.db.Where("username = ?", username).First(&user).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error("Error: ", err)
		return nil, err
	}

	log.Info("GetByUsername executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

func (ur *userRepository) GetByNameOrUsername(nameOrUsername string) ([]domain.User, error) {
	log := slog.With(
		slog.String("func", "GetByNameOrUsername"),
		slog.String("repository", "user"))

	log.Info("GetByNameOrUseraname initiated")

	var users []domain.User
	searchPattern := "%" + nameOrUsername + "%"
	err := ur.db.Where("name LIKE ? OR username LIKE ?", searchPattern, searchPattern).Find(&users).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error("Error: ", err)
		return nil, err
	}

	log.Info("GetByNameOrUsername executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return users, nil
}

func (ur *userRepository) GetByEmail(email string) (*domain.User, error) {
	log := slog.With(
		slog.String("func", "GetByEmail"),
		slog.String("repository", "user"))

	log.Info("GetByEmail initiated")

	var user domain.User
	err := ur.db.Where("email = ?", email).First(&user).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error("Error: ", err)
		return nil, err
	}

	log.Info("GetByEmail executed successfully")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	return &user, nil
}

func (ur *userRepository) Update(id string, user domain.User) error {
	log := slog.With(
		slog.String("func", "Create"),
		slog.String("repository", "user"))
	log.Info("Update initiated")

	err := ur.db.Model(&domain.User{}).Where("id = ?", id).Updates(domain.User{Name: user.Name, Email: user.Email}).Error
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("Update executed successfully")
	return nil
}

func (ur *userRepository) Delete(id string) error {
	log := slog.With(
		slog.String("func", "Delete"),
		slog.String("repository", "user"))

	log.Info("Delete initiated")

	err := ur.db.Delete(&domain.User{}, "id = ?", id).Error
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("Delete executed successfully")
	return nil
}

func (ur *userRepository) UpdatePassword(id string, password string) error {
	log := slog.With(
		slog.String("func", "updatePassword"),
		slog.String("repository", "user"))

	log.Info("UpdatePassword initiated")

	err := ur.db.Model(&domain.User{}).Where("id = ?", id).Updates(domain.User{Password: password}).Error
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("UpdatePassword executed successfully")
	return nil
}

func (ur *userRepository) ConfirmedEmail(id string) error {
	log := slog.With(
		slog.String("func", "ConfirmedEmail"),
		slog.String("repository", "user"))

	log.Info("ConfirmedEmail initiated")

	err := ur.db.Model(&domain.User{}).Where("id = ?", id).Updates(domain.User{EmailConfirmed: true}).Error
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("ConfirmedEmail executed successfully")
	return nil
}
