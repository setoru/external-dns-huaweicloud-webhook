/*
Copyright 2023 GleSYS AB

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package logging

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func Init() {
	setLogLevel()
	setLogFormat()
}

func setLogFormat() {
	format := os.Getenv("LOG_FORMAT")
	if format == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{})
	}
}

func setLogLevel() {
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		log.SetLevel(log.InfoLevel)
	} else {
		if levelInt, err := strconv.Atoi(level); err == nil {
			log.SetLevel(log.Level(uint32(levelInt)))
		} else {
			levelInt, err := log.ParseLevel(level)
			if err != nil {
				log.SetLevel(log.InfoLevel)
				log.Errorf("Invalid log level '%s', defaulting to info", level)
			} else {
				log.SetLevel(levelInt)
			}
		}
	}
}
