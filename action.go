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

func (a *EmailOperator) Call(sender string) error {
	var (
		messageTextRaw []byte
		err            error
	)

	if config.EmailOperatorFrom == "" {
		return errOperatorFromEmpty
	}

	if config.EmailOperatorTo == "" {
		return errOperatorToEmpty
	}

	message := gomail.NewMessage()

	message.SetHeader("From", config.EmailOperatorFrom)
	message.SetHeader("To", config.EmailOperatorTo)
	message.SetHeader("Subject", config.EmailOperatorSubject)

	if messageTextRaw, err = os.ReadFile(config.EmailOperatorMessagePath); err != nil {
		return err
	}

	messageText := string(messageTextRaw)
	if !strings.Contains(messageText, "%s") {
		return errMacroPercentS
	}

	if strings.Count(messageText, "%s") != 1 {
		return errMacroPercentSOnce
	}

	messageText = fmt.Sprintf(messageText, sender)
	message.SetBody(config.EmailOperatorMessageCT, messageText)

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

	if err = dialer.DialAndSend(message); err != nil {
		return err
	}

	return nil
}
