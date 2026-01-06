package sender

import (
	"auth/internal/config"
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
)

type EmailSender interface {
	SendVerificationCode(toEmail, userName, code string) error
}

type TemplateData struct {
	UserName      string
	Code          string
	AppName       string
	AppURL        string
	SupportEmail  string
	ExpiryMinutes int
}

type sender struct {
	config   config.SMTPConfig
	template *template.Template
}

func NewEmailSender(config config.SMTPConfig) (EmailSender, error) {
	templatePath := "C:\\auth\\internal\\sender\\templates\\verification_inline6.html"

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email template: %w", err)
	}

	return &sender{
		config:   config,
		template: tmpl,
	}, nil
}

func (s *sender) SendVerificationCode(toEmail, userName, code string) error {
	log.Printf("[SMTP] Sending verification code to: %s, code: %s", toEmail, code)

	data := TemplateData{
		UserName:      userName,
		Code:          code,
		AppName:       s.config.FromName,
		AppURL:        s.config.AppURL,
		SupportEmail:  s.config.SupportEmail,
		ExpiryMinutes: 3,
	}

	var body bytes.Buffer
	if err := s.template.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}



	return s.sendEmail(toEmail, body.String())
}

func (s *sender) sendEmail(to,  body string) error {
	log.Printf("[SMTP] Preparing email to: %s", to)
	log.Printf("[SMTP] SMTP: %s:%s", s.config.Host, s.config.Port)

	msg := fmt.Sprintf("From: %s <%s>\r\n", s.config.FromName, s.config.FromEmail)
	msg += fmt.Sprintf("To: %s\r\n", to)
	msg += fmt.Sprintf("Subject: %s\r\n", "Ваш код подтверждения")
	msg += "MIME-version: 1.0;\r\n"
	msg += "Content-Type: text/html; charset=\"UTF-8\";\r\n"
	msg += "\r\n" + body + "\r\n"

	smtpAddr := fmt.Sprintf("%s:%s", s.config.Host, s.config.Port)
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)

	log.Printf("[SMTP] Attempting to send...")
	err := smtp.SendMail(smtpAddr, auth, s.config.FromEmail, []string{to}, []byte(msg))
	if err != nil {
		log.Printf("[SMTP] ERROR sending: %v", err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("[SMTP] Email sent successfully to: %s", to)
	return nil
}
