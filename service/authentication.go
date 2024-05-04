package service

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/OVillas/autentication/models"
	"github.com/OVillas/autentication/util"
)

var confirmationsCodes map[string]models.ConfirmationCode

func init() {
	confirmationsCodes = make(map[string]models.ConfirmationCode)
}

type authenticationService struct {
	userRepository models.UserRepository
	emailService   models.EmailService
}

func NewAuthenticationService(userRepository models.UserRepository, emailService models.EmailService) models.AuthenticationService {
	return &authenticationService{
		userRepository: userRepository,
		emailService:   emailService,
	}
}

func (a *authenticationService) Login(login models.Login) (string, error) {
	log := slog.With(
		slog.String("func", "Login"),
		slog.String("service", "authentication"))

	log.Info("Login service initiated")
	var user *models.User
	var err error

	var getBy func(string) (*models.User, error)

	if util.IsEmailValid(login.Username) {
		getBy = a.userRepository.GetByEmail
	} else {
		getBy = a.userRepository.GetByUsername
	}

	user, err = getBy(login.Username)
	if err != nil {
		log.Warn("Failed to obtain user")
		return "", models.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this username: " + login.Username)
		return "", models.ErrUserNotFound
	}

	if err := CheckPassword(user.Password, login.Password); err != nil {
		log.Warn("invalid password for email: " + user.Email)
		return "", models.ErrPasswordNotMatch
	}

	token, err := util.CreateToken(*user)
	if err != nil {
		log.Error("error trying create token jwt. Error: ", err)
		return "", models.ErrGenToken
	}

	log.Info("Login executed successfully")
	return token, nil
}

func (a *authenticationService) UpdatePassword(id string, updatePassword models.UpdatePassword) error {
	log := slog.With(
		slog.String("func", "Login"),
		slog.String("service", "authentication"))

	log.Info("Update password service initiated")

	user, err := a.userRepository.GetById(id)
	if err != nil {
		log.Error("failed to get user by id")
		return models.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this id")
		return models.ErrUserNotFound
	}

	if err := CheckPassword(user.Password, updatePassword.Current); err != nil {
		log.Warn("current password not match ")
		return models.ErrPasswordNotMatch
	}

	newHashedPassword, err := Hash(updatePassword.New)
	if err != nil {
		log.Error("Error trying to hashed password")
		return models.ErrHashPassword
	}

	if err := a.userRepository.UpdatePassword(id, string(newHashedPassword)); err != nil {
		log.Error("Error: ", err)
		return models.ErrUpdatePassword
	}

	log.Info("Password updated successfully")
	return nil
}

func (a *authenticationService) SendConfirmationCode(email string) error {
	log := slog.With(
		slog.String("func", "SendConfirmationEmailCode"),
		slog.String("service", "authentication"))

	log.Info("SendingConfirmationEmail code service initiated")

	otp := models.ConfirmationCode{
		Code:       util.GenerateOTP(6),
		ExpiryTime: time.Now().Add(time.Hour),
	}

	a.addOrUpdateConfirmationCode(email, otp)

	subject := "Confirmação de cadastro"
	content := fmt.Sprintf("<h1>Olá!</h1><p>Seu código de confirmação é: <h2><b>%s</b></h2></p>", otp.Code)
	to := []string{email}

	err := a.emailService.SendEmail(subject, content, to)
	if err != nil {
		log.Error("Errors: ", err)
		return models.ErrToSendConfirmationCode
	}
	log.Info("Confirmation send successfully")

	return nil
}

func (a *authenticationService) ConfirmEmail(confirmCode models.ConfirmCode) error {
	log := slog.With(
		slog.String("func", "ConfirmEmail"),
		slog.String("service", "authentication"))

	log.Info("ConfirmingEmail service initiated")

	user, err := a.confirmCode(confirmCode)
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	if err := a.userRepository.ConfirmedEmail(user.ID); err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("Confirmed email successfully")
	return nil
}

func (a *authenticationService) CheckUserIDMatch(idFromToken string) error {
	log := slog.With(
		slog.String("func", "CheckUserIDMatch"),
		slog.String("service", "authentication"))

	log.Info("CheckUserIDMatch service initiated")

	user, err := a.userRepository.GetById(idFromToken)
	if err != nil {
		log.Warn("Failed to obtain user by id")
		return models.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this id: " + idFromToken)
		return models.ErrUserNotFound
	}

	if user.ID != idFromToken {
		log.Warn("User ID mismatch")
		return models.ErrUserIDMismatch
	}

	return nil
}

func (a *authenticationService) ConfirmResetPasswordCode(confirmCode models.ConfirmCode) (string, error) {
	log := slog.With(
		slog.String("func", "ConfirmResetPasswordCode"),
		slog.String("service", "authentication"))

	log.Info("Confirming reset password code service initiated")

	user, err := a.confirmCode(confirmCode)
	if err != nil {
		log.Error("Error: ", err)
		return "", err
	}

	log.Info("Code confirmed successfully")
	token, err := util.CreateResetPasswordToken(*user)
	if err != nil {
		log.Error("Error trying to create reset password token jwt. Error: ", err)
		return "", models.ErrGenToken
	}
	return token, nil
}

func (a *authenticationService) ResetPassword(userId string, resetPassword models.ResetPassword) error {
	log := slog.With(
		slog.String("func", "ResetPassword"),
		slog.String("service", "authentication"))

	log.Info("Reset password service initiated")
	
	user, err := a.userRepository.GetById(userId)
	if err != nil {
		log.Error("Failed to obtain user by id")
		return models.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this id")
		return models.ErrUserNotFound
	}

	if resetPassword.New != resetPassword.Confirm {
		log.Warn("Passwords do not match")
		return models.ErrPasswordNotMatch
	}

	newHashedPassword, err := Hash(resetPassword.New)
	if err != nil {
		log.Error("Error trying to hashed password")
		return models.ErrHashPassword
	}

	if err := a.userRepository.UpdatePassword(user.ID, string(newHashedPassword)); err != nil {
		log.Error("Error: ", err)
		return models.ErrUpdatePassword
	}

	log.Info("Password reset successfully")
	return nil
}

// Private session
func (a *authenticationService) addOrUpdateConfirmationCode(email string, code models.ConfirmationCode) {
	log := slog.With(
		slog.String("func", "addOrUpdateConfirmationCode"),
		slog.String("service", "authentication"))

	log.Info("Add or updating confirmation code initiated")

	if existingCode, ok := confirmationsCodes[email]; ok {
		existingCode.Code = code.Code
		existingCode.ExpiryTime = code.ExpiryTime
		confirmationsCodes[email] = existingCode
	} else {
		confirmationsCodes[email] = code
	}

	log.Info("Confirmation code added or updated successfully")
}

func (a *authenticationService) confirmCode(confirmCode models.ConfirmCode) (*models.User, error) {
	log := slog.With(
		slog.String("func", "confirmCode"),
		slog.String("service", "authentication"))

	log.Info("Confirming code service initiated")

	user, err := a.userRepository.GetByEmail(confirmCode.Email)
	if err != nil {
		log.Warn("Failed to obtain user by email")
		return nil, models.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this email: " + confirmCode.Email)
		return nil, models.ErrUserNotFound
	}

	confirmationCode, ok := confirmationsCodes[confirmCode.Email]
	if !ok {
		log.Error("OTP not found with this email: " + confirmCode.Email)
		return nil, models.ErrOTPNotFound
	}

	if time.Now().After(confirmationCode.ExpiryTime) {
		log.Warn("Token expired")
		return nil, models.ErrInvalidOTP
	}

	if confirmationCode.Code != confirmCode.Code {
		log.Warn("incorrect token")
		return nil, models.ErrInvalidOTP
	}

	log.Info("Code confirmed successfully")
	return user, nil
}
