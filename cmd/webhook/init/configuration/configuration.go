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

package configuration

import (
	"time"

	"github.com/caarlos0/env/v8"
	log "github.com/sirupsen/logrus"
)

// Config struct for configuration environmental variables
type Config struct {
	ServerHost           string        `env:"SERVER_HOST" envDefault:"localhost"`
	ServerPort           int           `env:"SERVER_PORT" envDefault:"8888"`
	ServerReadTimeout    time.Duration `env:"SERVER_READ_TIMEOUT"`
	ServerWriteTimeout   time.Duration `env:"SERVER_WRITE_TIMEOUT"`
	DomainFilter         []string      `env:"DOMAIN_FILTER" envDefault:""`
	ExcludeDomains       []string      `env:"EXCLUDE_DOMAINS" envDefault:""`
	ZoneNameFilter       []string      `env:"ZONE_NAME_FILTER" envDefault:""`
	ZoneIDFilter         []string      `env:"ZONE_ID_FILTER" envDefault:""`
	RegexDomainFilter    string        `env:"REGEXP_DOMAIN_FILTER" envDefault:""`
	RegexDomainExclusion string        `env:"REGEXP_DOMAIN_FILTER_EXCLUSION" envDefault:""`
	DryRun               bool          `env:"DRY_RUN" envDefault:"false"`
	ConfigFile           string        `env:"CONFIG_FILE" envDefault:"/etc/kubernetes/huawei-cloud.yaml"`
	ZoneType             string        `env:"ZONE_TYPE" envDefault:"public"`
	TokenFile            string        `env:"TOKEN_FILE" envDefault:""`
	ZoneMatchParent      bool          `env:"ZONE_MATCH_PARENT" envDefault:"false"`
	ExpirationSeconds    int64         `env:"EXPIRATION_SECONDS" envDefault:"7200"`
}

// Init sets up configuration by reading set environmental variables
func Init() Config {
	cfg := Config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("Error reading configuration from environment: %v", err)
	}
	return cfg
}
