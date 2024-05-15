package service

import (
	"log/slog"

	"github.com/OVillas/autentication/domain"
	"github.com/OVillas/autentication/secure"
	"github.com/OVillas/autentication/util"
	"github.com/samber/do"
)

type userPasswordService struct {
	i                       *do.Injector
	userRepository          domain.UserRepository
	confirmationCodeService domain.ConfirmationCodeService
}

func NewUserPasswordService(i *do.Injector) domain.UserPasswordService {
	userRepository := do.MustInvoke[domain.UserRepository](i)
	confimatioCodeService := do.MustInvoke[domain.ConfirmationCodeService](i)
	return &userPasswordService{
		i:                       i,
		userRepository:          userRepository,
		confirmationCodeService: confimatioCodeService,
	}
}

func (ups *userPasswordService) UpdatePassword(id string, updatePassword domain.UpdatePassword) error {
	log := slog.With(
		slog.String("service", "userPassword"),
		slog.String("func", "Login"))

	log.Info("UpdatePassword initiated")

	user, err := ups.userRepository.GetById(id)
	if err != nil {
		log.Error("failed to get user by id")
		return domain.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this id")
		return domain.ErrUserNotFound
	}

	if err := secure.CheckPassword(user.Password, updatePassword.Current); err != nil {
		log.Warn("current password not match ")
		return domain.ErrPasswordNotMatch
	}

	newHashedPassword, err := secure.Hash(updatePassword.New)
	if err != nil {
		log.Error("Error trying to hashed password")
		return domain.ErrHashPassword
	}

	if err := ups.userRepository.UpdatePassword(id, string(newHashedPassword)); err != nil {
		log.Error("Error: ", err)
		return domain.ErrUpdatePassword
	}

	log.Info("UpdatePassword executed successfully")
	return nil
}

func (ups *userPasswordService) ConfirmResetPasswordCode(confirmCode domain.ConfirmCode) (string, error) {
	log := slog.With(
		slog.String("service", "userPassword"),
		slog.String("func", "ConfirmResetPasswordCode"))

	log.Info("ConfirmingResetPassword code service initiated")

	user, err := ups.confirmationCodeService.ConfirmCode(confirmCode)
	if err != nil {
		log.Error("Error: ", err)
		return "", err
	}

	token, err := util.CreateResetPasswordToken(*user)
	if err != nil {
		log.Error("Error trying to create reset password token jwt. Error: ", err)
		return "", domain.ErrGenToken
	}

	log.Info("ConfirmResetPasswordCode executed successfully")
	return token, nil
}

func (ups *userPasswordService) ResetPassword(userId string, resetPassword domain.ResetPassword) error {
	log := slog.With(
		slog.String("service", "userPassword"),
		slog.String("func", "ResetPassword"))

	log.Info("Reset password service initiated")

	user, err := ups.userRepository.GetById(userId)
	if err != nil {
		log.Error("Failed to obtain user by id")
		return domain.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this id")
		return domain.ErrUserNotFound
	}

	if resetPassword.New != resetPassword.Confirm {
		log.Warn("Passwords do not match")
		return domain.ErrPasswordNotMatch
	}

	newHashedPassword, err := secure.Hash(resetPassword.New)
	if err != nil {
		log.Error("Error trying to hashed password")
		return domain.ErrHashPassword
	}

	if err := ups.userRepository.UpdatePassword(user.ID, string(newHashedPassword)); err != nil {
		log.Error("Error: ", err)
		return domain.ErrUpdatePassword
	}

	log.Info("ResetPassword executed successfully")
	return nil
}
