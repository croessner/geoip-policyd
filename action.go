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
	"gopkg.in/gomail.v2"
	"io/ioutil"
	"log"
	"strings"
)

type Action interface {
	// Call an action with 'sender' and a configuration as arguments. Report errors
	Call(string, interface{}) error
}

type EmailOperator struct{}

func (a *EmailOperator) Call(sender string, c interface{}) error {
	cfg, ok := c.(*CmdLineConfig)
	if !ok {
		return fmt.Errorf("config argument must be of type *CmdLineConfig")
	}

	if cfg.EmailOperatorFrom == "" {
		return fmt.Errorf("operator 'from' must not be empty")
	}
	if cfg.EmailOperatorTo == "" {
		return fmt.Errorf("operator 'to' must not be empty")
	}

	m := gomail.NewMessage()

	m.SetHeader("From", cfg.EmailOperatorFrom)
	m.SetHeader("To", cfg.EmailOperatorTo)
	m.SetHeader("Subject", cfg.EmailOperatorSubject)

	if messageTextRaw, err := ioutil.ReadFile(cfg.EmailOperatorMessagePath); err != nil {
		return err
	} else {
		messageText := string(messageTextRaw)
		if !strings.Contains(messageText, "%s") {
			return fmt.Errorf("email message file must contain a macro '%%s' for the sender")
		}
		if strings.Count(messageText, "%s") != 1 {
			return fmt.Errorf("email message file must contain exactly one '%%s' macro for the sender")
		}
		messageText = fmt.Sprintf(messageText, sender)
		m.SetBody(cfg.EmailOperatorMessageCT, messageText)
	}

	d := &gomail.Dialer{Host: cfg.MailServer, Port: cfg.MailPort}
	d.SSL = cfg.MailSSL
	if cfg.MailUsername != "" {
		d.Username = cfg.MailUsername
	}
	if cfg.MailPasswordPath != "" {
		password, err := ioutil.ReadFile(cfg.MailPasswordPath)
		if err != nil {
			log.Println("Error:", err)
			return err
		}
		d.Password = string(password)
	}
	d.TLSConfig = &tls.Config{ServerName: cfg.MailServer, InsecureSkipVerify: false}

	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}
