package service

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/OVillas/autentication/domain"
	"github.com/OVillas/autentication/secure"
	"github.com/OVillas/autentication/util"
)

var confirmationsCodes map[string]domain.ConfirmationCode

func init() {
	confirmationsCodes = make(map[string]domain.ConfirmationCode)
}

type userService struct {
	userRepository domain.UserRepository
	emailService   domain.EmailService
}

func NewUserService(userRepository domain.UserRepository, emailService domain.EmailService) domain.UserService {
	return &userService{
		userRepository: userRepository,
		emailService:   emailService,
	}
}

func (us *userService) Create(userPayLoad domain.UserPayLoad) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "Create"))

	log.Info("Create service initiated")

	userResponse, err := us.userRepository.GetByEmail(userPayLoad.Email)
	if err != nil {
		log.Error("Error trying to get user from repository")
		return domain.ErrGetUser
	}

	if userResponse != nil {
		log.Warn("There is already a registered user with this email: " + userPayLoad.Email)
		return domain.ErrUserAlreadyRegistered
	}

	hashedPassword, err := secure.Hash(userPayLoad.Password)
	if err != nil {
		log.Error("Error trying to hashed password")
		return domain.ErrHashPassword
	}

	user, err := userPayLoad.ToUser(string(hashedPassword))
	if err != nil {
		log.Error("Error trying to convert userPayload to User")
		return domain.ErrConvertUserPayLoadToUser
	}
	user.EmailConfirmed = false

	if err := us.userRepository.Create(*user); err != nil {
		log.Error("Error: ", err)
		return domain.ErrCreateUser
	}

	log.Info("success to create user")
	return nil
}

func (us *userService) GetAll() ([]domain.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetAll"))

	log.Info("GetAll service initiated")

	users, err := us.userRepository.GetAll()
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("get all service executed successfully")
	if users == nil {
		return nil, nil
	}

	var usersResponse []domain.UserResponse
	for _, user := range users {
		usersResponse = append(usersResponse, *user.ToUserResponse())
	}

	return usersResponse, nil
}

func (us *userService) GetById(id string) (*domain.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetById"))

	log.Info("GetById service initiated")

	user, err := us.userRepository.GetById(id)
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("get all service executed successfully")
	if user == nil {
		return nil, nil
	}

	userResponse := user.ToUserResponse()

	return userResponse, err
}

func (us *userService) GetByNameOrNick(name string) ([]domain.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetAll"))

	log.Info("GetAll service initiated")

	users, err := us.userRepository.GetByNameOrNick(name)
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("get all service executed successfully")
	if users == nil {
		return nil, nil
	}

	var usersResponse []domain.UserResponse
	for _, user := range users {
		usersResponse = append(usersResponse, *user.ToUserResponse())
	}

	return usersResponse, err
}

func (us *userService) GetByUsername(username string) (*domain.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetByEmail"))

	log.Info("GetByUsername service initiated")

	user, err := us.userRepository.GetByUsername(username)
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("get by email service executed successfully")
	if user == nil {
		return nil, nil
	}

	userResponse := user.ToUserResponse()

	return userResponse, nil
}

func (us *userService) GetByEmail(email string) (*domain.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetByEmail"))

	log.Info("GetByEmail service initiated")

	user, err := us.userRepository.GetByEmail(email)
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("get by email service executed successfully")
	if user == nil {
		return nil, nil
	}

	userResponse := user.ToUserResponse()

	return userResponse, nil
}

func (us *userService) Update(id string, userUpdate domain.UserUpdatePayLoad) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "update"))

	log.Info("Update service initiated")

	user, err := us.userRepository.GetById(id)
	if err != nil {
		log.Error("Error: ", err)
		return domain.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found to update")
		return domain.ErrUserNotFound
	}

	if user.Email == userUpdate.Email {
		log.Warn("Email same as above")
		return domain.ErrSameEmail
	}

	if userUpdate.Email != "" {
		user.Email = userUpdate.Email
	}

	if userUpdate.Name != "" {
		user.Name = userUpdate.Name
	}

	if err := us.userRepository.Update(id, *user); err != nil {
		log.Error("Error: ", err)
		return domain.ErrCreateUser
	}

	return nil
}

func (us *userService) Delete(id string) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "delete"))

	log.Info("Delete service initiated")

	user, err := us.userRepository.GetById(id)
	if err != nil {
		log.Error("Error trying to get user from repository")
		return domain.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found to delete")
		return domain.ErrUserNotFound
	}

	if err := us.userRepository.Delete(id); err != nil {
		log.Error("Error: ", err)
		return domain.ErrDeleteUser
	}

	return nil
}

func (us *userService) Login(login domain.Login) (string, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "Login"))

	log.Info("Login service initiated")
	var user *domain.User
	var err error

	var getBy func(string) (*domain.User, error)

	if util.IsEmailValid(login.Username) {
		getBy = us.userRepository.GetByEmail
	} else {
		getBy = us.userRepository.GetByUsername
	}

	user, err = getBy(login.Username)
	if err != nil {
		log.Warn("Failed to obtain user")
		return "", domain.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this username: " + login.Username)
		return "", domain.ErrUserNotFound
	}

	if err := secure.CheckPassword(user.Password, login.Password); err != nil {
		log.Warn("invalid password for email: " + user.Email)
		return "", domain.ErrPasswordNotMatch
	}

	token, err := util.CreateToken(*user)
	if err != nil {
		log.Error("error trying create token jwt. Error: ", err)
		return "", domain.ErrGenToken
	}

	log.Info("Login executed successfully")
	return token, nil
}

func (us *userService) UpdatePassword(id string, updatePassword domain.UpdatePassword) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "Login"))

	log.Info("Update password service initiated")

	user, err := us.userRepository.GetById(id)
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

	if err := us.userRepository.UpdatePassword(id, string(newHashedPassword)); err != nil {
		log.Error("Error: ", err)
		return domain.ErrUpdatePassword
	}

	log.Info("Password updated successfully")
	return nil
}

func (us *userService) SendConfirmationCode(email string) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "SendConfirmationEmailCode"))

	log.Info("SendingConfirmationEmail code service initiated")

	otp := domain.ConfirmationCode{
		Code:       util.GenerateOTP(6),
		ExpiryTime: time.Now().Add(time.Hour),
	}

	us.addOrUpdateConfirmationCode(email, otp)

	subject := "Confirmação de cadastro"
	content := fmt.Sprintf("<h1>Olá!</h1><p>Seu código de confirmação é: <h2><b>%s</b></h2></p>", otp.Code)
	to := []string{email}

	err := us.emailService.SendEmail(subject, content, to)
	if err != nil {
		log.Error("Errors: ", err)
		return domain.ErrToSendConfirmationCode
	}
	log.Info("Confirmation send successfully")

	return nil
}

func (us *userService) ConfirmEmail(confirmCode domain.ConfirmCode) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "ConfirmEmail"))

	log.Info("ConfirmingEmail service initiated")

	user, err := us.confirmCode(confirmCode)
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	if err := us.userRepository.ConfirmedEmail(user.ID); err != nil {
		log.Error("Error: ", err)
		return err
	}

	log.Info("Confirmed email successfully")
	return nil
}

func (us *userService) CheckUserIDMatch(idFromToken string) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "CheckUserIDMatch"))

	log.Info("CheckUserIDMatch service initiated")

	user, err := us.userRepository.GetById(idFromToken)
	if err != nil {
		log.Warn("Failed to obtain user by id")
		return domain.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this id: " + idFromToken)
		return domain.ErrUserNotFound
	}

	if user.ID != idFromToken {
		log.Warn("User ID mismatch")
		return domain.ErrUserIDMismatch
	}

	return nil
}

func (us *userService) ConfirmResetPasswordCode(confirmCode domain.ConfirmCode) (string, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "ConfirmResetPasswordCode"))

	log.Info("Confirming reset password code service initiated")

	user, err := us.confirmCode(confirmCode)
	if err != nil {
		log.Error("Error: ", err)
		return "", err
	}

	log.Info("Code confirmed successfully")
	token, err := util.CreateResetPasswordToken(*user)
	if err != nil {
		log.Error("Error trying to create reset password token jwt. Error: ", err)
		return "", domain.ErrGenToken
	}
	return token, nil
}

func (us *userService) ResetPassword(userId string, resetPassword domain.ResetPassword) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "ResetPassword"))

	log.Info("Reset password service initiated")

	user, err := us.userRepository.GetById(userId)
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

	if err := us.userRepository.UpdatePassword(user.ID, string(newHashedPassword)); err != nil {
		log.Error("Error: ", err)
		return domain.ErrUpdatePassword
	}

	log.Info("Password reset successfully")
	return nil
}

// Private session
func (us *userService) addOrUpdateConfirmationCode(email string, code domain.ConfirmationCode) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "addOrUpdateConfirmationCode"))

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

func (us *userService) confirmCode(confirmCode domain.ConfirmCode) (*domain.User, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "confirmCode"))

	log.Info("Confirming code service initiated")

	user, err := us.userRepository.GetByEmail(confirmCode.Email)
	if err != nil {
		log.Warn("Failed to obtain user by email")
		return nil, domain.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found with this email: " + confirmCode.Email)
		return nil, domain.ErrUserNotFound
	}

	confirmationCode, ok := confirmationsCodes[confirmCode.Email]
	if !ok {
		log.Error("OTP not found with this email: " + confirmCode.Email)
		return nil, domain.ErrOTPNotFound
	}

	if time.Now().After(confirmationCode.ExpiryTime) {
		log.Warn("Token expired")
		return nil, domain.ErrInvalidOTP
	}

	if confirmationCode.Code != confirmCode.Code {
		log.Warn("incorrect token")
		return nil, domain.ErrInvalidOTP
	}

	log.Info("Code confirmed successfully")
	return user, nil
}
