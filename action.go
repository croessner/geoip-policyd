/*
geoip-policyd
Copyright (C) 2021  Rößner-Network-Solutions

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
	Call(string, interface{}) error
}

type EmailOperator struct{}

func (a *EmailOperator) Call(sender string, cmdLineConfig any) error {
	var (
		messageTextRaw []byte
		err            error
	)

	cfg, ok := cmdLineConfig.(*CmdLineConfig)
	if !ok {
		return errCmdLineConfig
	}

	if cfg.EmailOperatorFrom == "" {
		return errOperatorFromEmpty
	}

	if cfg.EmailOperatorTo == "" {
		return errOperatorToEmpty
	}

	message := gomail.NewMessage()

	message.SetHeader("From", cfg.EmailOperatorFrom)
	message.SetHeader("To", cfg.EmailOperatorTo)
	message.SetHeader("Subject", cfg.EmailOperatorSubject)

	if messageTextRaw, err = os.ReadFile(cfg.EmailOperatorMessagePath); err != nil {
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
	message.SetBody(cfg.EmailOperatorMessageCT, messageText)

	dialer := &gomail.Dialer{Host: cfg.MailServer, Port: cfg.MailPort}
	dialer.SSL = cfg.MailSSL

	if cfg.MailUsername != "" {
		dialer.Username = cfg.MailUsername
	}

	if cfg.MailPassword != "" {
		dialer.Password = cfg.MailPassword
	}

	if cfg.MailHelo != "" {
		dialer.LocalName = cfg.MailHelo
	}

	dialer.TLSConfig = &tls.Config{
		ServerName:         cfg.MailServer,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}

	if err := dialer.DialAndSend(message); err != nil {
		return err
	}

	return nil
}
