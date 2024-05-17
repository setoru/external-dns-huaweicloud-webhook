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

package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/setoru/external-dns-huaweicloud-webhook/dnsprovider"
	"github.com/setoru/external-dns-huaweicloud-webhook/webhook"
	"github.com/setoru/external-dns-huaweicloud-webhook/webhook/configuration"
	"github.com/setoru/external-dns-huaweicloud-webhook/webhook/logging"
	"github.com/setoru/external-dns-huaweicloud-webhook/webhook/server"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/provider"
)

const banner = `
  ________.____     ___________  _____________.___. _________
 /  _____/|    |    \_   _____/ /  _____/\__  |   |/   _____/
/   \  ___|    |     |    __)_  \____  \  /   |   |\_____  \
\    \_\  \    |___  |        \/        \ \____   |/        \
 \______  /_______ \/_______  /_______  / / ______/_______  /
        \/        \/        \/        \/  \/              \/

 external-dns-huaweicloud

`

func main() {
	logging.Init()
	config := configuration.Init()
	var domainFilter endpoint.DomainFilter
	createMsg := "Creating HuaweiCloud provider with "

	if config.RegexDomainFilter != "" {
		createMsg += fmt.Sprintf("Regexp domain filter: '%s', ", config.RegexDomainFilter)
		if config.RegexDomainExclusion != "" {
			createMsg += fmt.Sprintf("with exclusion: '%s', ", config.RegexDomainExclusion)
		}
		domainFilter = endpoint.NewRegexDomainFilter(
			regexp.MustCompile(config.RegexDomainFilter),
			regexp.MustCompile(config.RegexDomainExclusion),
		)
	} else {
		if config.DomainFilter != nil && len(config.DomainFilter) > 0 {
			createMsg += fmt.Sprintf("zoneNode filter: '%s', ", strings.Join(config.DomainFilter, ","))
		}
		if config.ExcludeDomains != nil && len(config.ExcludeDomains) > 0 {
			createMsg += fmt.Sprintf("Exclude domain filter: '%s', ", strings.Join(config.ExcludeDomains, ","))
		}
		domainFilter = endpoint.NewDomainFilterWithExclusions(config.DomainFilter, config.ExcludeDomains)
	}
	zoneIDFilter := provider.NewZoneIDFilter(config.ZoneIDFilter)
	provider, err := dnsprovider.NewHuaweiCloudProvider(domainFilter, zoneIDFilter, config.ConfigFile, config.ZoneType, config.DryRun, config.TokenFile, config.ZoneMatchParent)
	if err != nil {
		log.Fatalf("Failed to initialize DNS provider: %v", err)
	}
	srv := server.Init(config, webhook.New(provider))
	server.ShutdownGracefully(srv)
}
