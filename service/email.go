package service

import (
	"net/smtp"
	"strconv"

	"github.com/OVillas/autentication/config"
	"github.com/OVillas/autentication/domain"
	"github.com/samber/do"
)

type emailService struct {
	i           *do.Injector
	gmailSender domain.GmailSender
}

func NewEmailService(i *do.Injector) (domain.EmailService, error) {
	gmailSender := domain.GmailSender{
		Name:              config.EmailSenderName,
		FromEmailAddress:  config.EmailSender,
		FromEmailPassword: config.EmailSenderPassword,
	}

	return &emailService{
		i:           i,
		gmailSender: gmailSender,
	}, nil
}

func (sender *emailService) SendEmail(subject string, content string, to []string) error {
	message := []byte("Subject: " + subject + "\r\n" +
		"From: " + sender.gmailSender.Name + " <" + sender.gmailSender.FromEmailAddress + ">\r\n" +
		"To: " + to[0] + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		content)

	auth := smtp.PlainAuth("", sender.gmailSender.FromEmailAddress, sender.gmailSender.FromEmailPassword, config.SMTPServer)

	smtpPortStr := strconv.Itoa(config.SMTPPort)

	err := smtp.SendMail(config.SMTPServer+":"+smtpPortStr, auth, sender.gmailSender.FromEmailAddress, to, message)
	if err != nil {
		return err
	}

	return nil
}
