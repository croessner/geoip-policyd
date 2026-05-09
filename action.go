// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package main implements the geoip-policyd service and helper commands.
package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"gopkg.in/gomail.v2"
)

type Action interface {
	// Call an action with 'sender' and a configuration as arguments. Report errors
	Call(string) error
}

type EmailOperator struct{}

// newMessage validates operator settings and renders the configured message body.
func (a *EmailOperator) newMessage(sender string) (*gomail.Message, error) {
	if config.EmailOperatorFrom == "" {
		return nil, errOperatorFromEmpty
	}

	if config.EmailOperatorTo == "" {
		return nil, errOperatorToEmpty
	}

	messageTextRaw, err := os.ReadFile(config.EmailOperatorMessagePath)
	if err != nil {
		return nil, err
	}

	messageText := string(messageTextRaw)
	if !strings.Contains(messageText, "%s") {
		return nil, errMacroPercentS
	}

	if strings.Count(messageText, "%s") != 1 {
		return nil, errMacroPercentSOnce
	}

	message := gomail.NewMessage()
	message.SetHeader("From", config.EmailOperatorFrom)
	message.SetHeader("To", config.EmailOperatorTo)
	message.SetHeader("Subject", config.EmailOperatorSubject)
	message.SetBody(config.EmailOperatorMessageCT, fmt.Sprintf(messageText, sender))

	return message, nil
}

// newDialer creates the SMTP dialer from the current operator mail configuration.
func (a *EmailOperator) newDialer() *gomail.Dialer {
	dialer := &gomail.Dialer{Host: config.MailServer, Port: config.MailPort, SSL: config.MailSSL}
	dialer.SSL = config.MailSSL

	if config.MailUsername != "" {
		dialer.Username = config.MailUsername
	}

	if config.MailPassword != "" {
		dialer.Password = config.MailPassword
	}

	if config.MailHelo != "" {
		dialer.LocalName = config.MailHelo
	}

	if config.MailSSL {
		dialer.TLSConfig = &tls.Config{
			ServerName:         config.MailServer,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		}
	}

	return dialer
}

func (a *EmailOperator) Call(sender string) error {
	message, err := a.newMessage(sender)
	if err != nil {
		return err
	}

	if err = a.newDialer().DialAndSend(message); err != nil {
		return err
	}

	return nil
}
