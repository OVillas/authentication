package service

import (
	"log/slog"

	"github.com/OVillas/autentication/models"
)

type userService struct {
	userRepository models.UserRepository
}

func NewUserService(userRepository models.UserRepository) models.UserService {
	return userService{
		userRepository: userRepository,
	}
}

func (us userService) Create(userPayLoad models.UserPayLoad) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "Create"))

	log.Info("Create service initiated")

	userResponse, err := us.userRepository.GetByEmail(userPayLoad.Email)
	if err != nil {
		log.Error("Error trying to get user from repository")
		return models.ErrGetUser
	}

	if userResponse != nil {
		log.Warn("There is already a registered user with this email: " + userPayLoad.Email)
		return models.ErrUserAlreadyRegistered
	}

	hashedPassword, err := Hash(userPayLoad.Password)
	if err != nil {
		log.Error("Error trying to hashed password")
		return models.ErrHashPassword
	}

	user, err := userPayLoad.ToUser(string(hashedPassword))
	if err != nil {
		log.Error("Error trying to convert userPayload to User")
		return models.ErrConvertUserPayLoadToUser
	}
	user.EmailConfirmed = false

	if err := us.userRepository.Create(*user); err != nil {
		log.Error("Error: ", err)
		return models.ErrCreateUser
	}

	log.Info("success to create user")
	return nil
}

func (us userService) GetAll() ([]models.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetAll"))

	log.Info("GetAll service initiated")

	users, err := us.userRepository.GetAll()
	if err != nil {
		log.Error("Error: ", err)
		return nil, models.ErrGetUser
	}

	log.Info("get all service executed successfully")
	if users == nil {
		return nil, nil
	}

	var usersResponse []models.UserResponse
	for _, user := range users {
		usersResponse = append(usersResponse, *user.ToUserResponse())
	}

	return usersResponse, nil
}

func (us userService) GetById(id string) (*models.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetById"))

	log.Info("GetById service initiated")

	user, err := us.userRepository.GetById(id)
	if err != nil {
		log.Error("Error: ", err)
		return nil, models.ErrGetUser
	}

	log.Info("get all service executed successfully")
	if user == nil {
		return nil, nil
	}

	userResponse := user.ToUserResponse()

	return userResponse, err
}

func (us userService) GetByNameOrNick(name string) ([]models.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetAll"))
	
	log.Info("GetAll service initiated")

	users, err := us.userRepository.GetByNameOrNick(name)
	if err != nil {
		log.Error("Error: ", err)
		return nil, models.ErrGetUser
	}

	log.Info("get all service executed successfully")
	if users == nil {
		return nil, nil
	}

	var usersResponse []models.UserResponse
	for _, user := range users {
		usersResponse = append(usersResponse, *user.ToUserResponse())
	}

	return usersResponse, err
}

func (us userService) GetByUsername(username string) (*models.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetByEmail"))

	log.Info("GetByUsername service initiated")

	user, err := us.userRepository.GetByUsername(username)
	if err != nil {
		log.Error("Error: ", err)
		return nil, models.ErrGetUser
	}

	log.Info("get by email service executed successfully")
	if user == nil {
		return nil, nil
	}

	userResponse := user.ToUserResponse()

	return userResponse, nil
}

func (us userService) GetByEmail(email string) (*models.UserResponse, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "GetByEmail"))

	log.Info("GetByEmail service initiated")

	user, err := us.userRepository.GetByEmail(email)
	if err != nil {
		log.Error("Error: ", err)
		return nil, models.ErrGetUser
	}

	log.Info("get by email service executed successfully")
	if user == nil {
		return nil, nil
	}

	userResponse := user.ToUserResponse()

	return userResponse, nil
}

func (us userService) Update(id string, userUpdate models.UserUpdatePayLoad) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "update"))
	
	log.Info("Update service initiated")

	user, err := us.userRepository.GetById(id)
	if err != nil {
		log.Error("Error: ", err)
		return models.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found to update")
		return models.ErrUserNotFound
	}

	if user.Email == userUpdate.Email {
		log.Warn("Email same as above")
		return models.ErrSameEmail
	}

	if userUpdate.Email != "" {
		user.Email = userUpdate.Email
	}

	if userUpdate.Name != "" {
		user.Name = userUpdate.Name
	}

	if err := us.userRepository.Update(id, *user); err != nil {
		log.Error("Error: ", err)
		return models.ErrCreateUser
	}

	return nil
}

func (us userService) Delete(id string) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "delete"))
	
	log.Info("Delete service initiated")

	user, err := us.userRepository.GetById(id)
	if err != nil {
		log.Error("Error trying to get user from repository")
		return models.ErrGetUser
	}

	if user == nil {
		log.Warn("User not found to delete")
		return models.ErrUserNotFound
	}

	if err := us.userRepository.Delete(id); err != nil {
		log.Error("Error: ", err)
		return models.ErrDeleteUser
	}

	return nil
}
