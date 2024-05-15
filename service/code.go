package service

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/OVillas/autentication/domain"
	"github.com/OVillas/autentication/util"
	"github.com/samber/do"
)

var confirmationsCodes map[string]domain.ConfirmationCode

func init() {
	confirmationsCodes = make(map[string]domain.ConfirmationCode)
}

type confirmationCodeService struct {
	i              *do.Injector
	userRepository domain.UserRepository
	emailService   domain.EmailService
}

func NewCodeService(i *do.Injector) (domain.ConfirmationCodeService, error) {
	emailService := do.MustInvoke[domain.EmailService](i)
	userRepository := do.MustInvoke[domain.UserRepository](i)
	return &confirmationCodeService{
		i:              i,
		emailService:   emailService,
		userRepository: userRepository,
	}, nil
}

func (ccs *confirmationCodeService) SendConfirmationCode(email string) error {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "SendConfirmationEmailCode"))

	log.Info("SendConfirmationEmailCode service initiated")

	otp := domain.ConfirmationCode{
		Code:       util.GenerateOTP(6),
		ExpiryTime: time.Now().Add(time.Hour),
	}

	ccs.addOrUpdateConfirmationCode(email, otp)

	subject := "Confirmação de cadastro"
	content := fmt.Sprintf("<h1>Olá!</h1><p>Seu código de confirmação é: <h2><b>%s</b></h2></p>", otp.Code)
	to := []string{email}

	err := ccs.emailService.SendEmail(subject, content, to)
	if err != nil {
		log.Error("Errors: ", err)
		return domain.ErrToSendConfirmationCode
	}

	log.Info("SendConfirmationEmailCode executed successfully")
	return nil
}

func (c *confirmationCodeService) ConfirmCode(confirmCode domain.ConfirmCode) (*domain.User, error) {
	log := slog.With(
		slog.String("service", "user"),
		slog.String("func", "confirmCode"))

	log.Info("Confirming code service initiated")

	user, err := c.userRepository.GetByEmail(confirmCode.Email)
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

// Private session
func (ccs *confirmationCodeService) addOrUpdateConfirmationCode(email string, code domain.ConfirmationCode) {
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

	log.Info("Add or updating confirmation code executed successfully")
}
