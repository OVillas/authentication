package service

import (
	"log/slog"

	"github.com/OVillas/autentication/domain"
	"github.com/OVillas/autentication/secure"
	"github.com/OVillas/autentication/util"
	"github.com/samber/do"
)

type userService struct {
	i                     *do.Injector
	userRepository        domain.UserRepository
	emailService          domain.EmailService
	confimatioCodeService domain.ConfirmationCodeService
}

func NewUserService(i *do.Injector) (domain.UserService, error) {
	userRepository := do.MustInvoke[domain.UserRepository](i)
	emailService := do.MustInvoke[domain.EmailService](i)
	confimatioCodeService := do.MustInvoke[domain.ConfirmationCodeService](i)
	return &userService{
		i:                     i,
		userRepository:        userRepository,
		emailService:          emailService,
		confimatioCodeService: confimatioCodeService,
	}, nil
}

func (us *userService) Create(userPayLoad domain.UserPayLoad) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "Create"))

	log.Info("Create initiated")

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

	log.Info("Create executed successfully")
	return nil
}

func (us *userService) GetAll() ([]domain.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetAll"))

	log.Info("GetAll initiated")

	users, err := us.userRepository.GetAll()
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("get all executed successfully")
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

	log.Info("GetById initiated")

	user, err := us.userRepository.GetById(id)
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("GetById executed successfully")
	if user == nil {
		return nil, nil
	}

	userResponse := user.ToUserResponse()

	return userResponse, err
}

func (us *userService) GetByNameOrUsername(name string) ([]domain.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetByNameOrUsername"))

	log.Info("GetByNameOrUsername initiated")

	users, err := us.userRepository.GetByNameOrUsername(name)
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("GetByNameOrUsername executed successfully")
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
		slog.String("func", "GetByUsername"))

	log.Info("GetByUsername initiated")

	user, err := us.userRepository.GetByUsername(username)
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("GetByUsername executed successfully")
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

	log.Info("GetByEmail initiated")

	user, err := us.userRepository.GetByEmail(email)
	if err != nil {
		log.Error("Error: ", err)
		return nil, domain.ErrGetUser
	}

	log.Info("GetByEmail executed successfully")
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

	log.Info("Update initiated")

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

	log.Info("Update executed successfully")

	return nil
}

func (us *userService) Delete(id string) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "delete"))

	log.Info("Delete initiated")

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

	log.Info("Delete executed successfully")
	return nil
}

func (us *userService) Login(login domain.Login) (string, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "Login"))

	log.Info("Login initiated")
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

func (us *userService) ConfirmEmail(confirmCode domain.ConfirmCode) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "ConfirmEmail"))

	log.Info("Confirming email service initiated")

	user, err := us.confimatioCodeService.ConfirmCode(confirmCode)
	if err != nil {
		log.Error("Error: ", err)
		return err
	}

	if err := us.userRepository.ConfirmedEmail(user.ID); err != nil {
		log.Error("Error: ", err)
		return err
	}
	log.Info("ConfirmEmail executed uccessfully")
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

	log.Info("CheckUserIDMatch executed successfully")
	return nil
}
