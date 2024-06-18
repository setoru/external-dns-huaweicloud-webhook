/*
Copyright 2023 Huaweicloud

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

package dnsprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/region"
	hwdns "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2"
	dnsMdl "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/model"
	hwIam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	iamMdl "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"sigs.k8s.io/external-dns/plan"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/provider"
)

// HuaweicloudProvider is an implementation of Provider for HuaweiCloud DNS.
type HuaweicloudProvider struct {
	provider.BaseProvider
	// only consider hosted zones managing domains ending in this suffix
	domainFilter endpoint.DomainFilter
	// filter hosted zones by id
	zoneIDFilter provider.ZoneIDFilter
	dnsClient    HuaweiCloudDNSAPI
	dryRun       bool
	privateZone  bool
	// extend filter for sub-domains in the zone
	zoneMatchParent bool
	config          *HuaweiCloudConfig
	//vpcId of HuaweiCloud (optional)
	vpcID string
	//idp token
	tokenFile string
	//expiration seconds of the token
	expirationSeconds int64
	//expiration timestamp of the token
	expirationTime int64
}

// HuaweiCloudConfig contains configuration to create a new HuaweiCloud provider.
type HuaweiCloudConfig struct {
	AccessKey     string `json:"accessKey" yaml:"accessKey"`
	SecretKey     string `json:"secretKey" yaml:"secretKey"`
	SecurityToken string `json:"securityToken" yaml:"securityToken"`
	Region        string `json:"region" yaml:"region"`
	VpcID         string `json:"vpcId" yaml:"vpcId"`
	ProjectID     string `json:"projectId" yaml:"projectId"`
	IdpID         string `json:"idpId" yaml:"idpId"`
}

type RecordListGroup struct {
	domain  dnsMdl.PrivateZoneResp
	records []dnsMdl.ListRecordSets
}

// NewHuaweiCloudProvider initializes a new HuaweiCloud based Provider.
func NewHuaweiCloudProvider(domainFilter endpoint.DomainFilter, zoneIDFilter provider.ZoneIDFilter, configFile string, zoneType string, DryRun bool, tokenFile string, zoneMatchParent bool, expirationSeconds int64) (*HuaweicloudProvider, error) {
	cfg, err := parseConfig(configFile)
	if err != nil {
		return nil, err
	}

	var client HuaweiCloudDNSAPI
	var hcClient *core.HcHttpClient
	region := region.NewRegion(cfg.Region, fmt.Sprintf("https://dns.%s.myhuaweicloud.com", cfg.Region))
	if tokenFile != "" {
		var scopedToken string
		if scopedToken, err = getScopedTokenByIdpToken(tokenFile, cfg); err != nil {
			return nil, err
		}
		tokenAuth := hwIam.NewIamCredentialsBuilder().WithXAuthToken(scopedToken).Build()

		if err != nil {
			return nil, errors.Wrapf(err, "failed to get correct Huawei Cloud credential")
		}
		hcClient, err = hwdns.DnsClientBuilder().
			WithRegion(region).
			WithCredential(tokenAuth).
			WithCredentialsType("v3.IamCredentials").
			WithHttpConfig(config.DefaultHttpConfig()).
			SafeBuild()
	} else {
		// if token is empty, use static credentials
		basicAuth, err := basic.NewCredentialsBuilder().
			WithAk(cfg.AccessKey).
			WithSk(cfg.SecretKey).
			WithSecurityToken(cfg.SecurityToken).
			SafeBuild()
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get basic auth")
		}
		hcClient, err = hwdns.DnsClientBuilder().
			WithRegion(region).
			WithCredential(basicAuth).
			SafeBuild()
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get Huawei Cloud Client")
	}

	client = hwdns.NewDnsClient(hcClient)
	return &HuaweicloudProvider{
		domainFilter:      domainFilter,
		zoneIDFilter:      zoneIDFilter,
		dnsClient:         client,
		vpcID:             cfg.VpcID,
		privateZone:       zoneType == "private",
		dryRun:            DryRun,
		zoneMatchParent:   zoneMatchParent,
		config:            cfg,
		tokenFile:         tokenFile,
		expirationSeconds: expirationSeconds,
	}, nil
}

// refreshToken refresh the expired token when the token expires
func (p *HuaweicloudProvider) refreshToken() (err error) {
	if p.tokenFile == "" {
		log.Debugf("use static credentials")
		return
	}
	currentTime := time.Now().Unix()
	if currentTime < p.expirationTime && p.expirationTime != 0 {
		return
	}
	p.expirationTime = currentTime + p.expirationSeconds
	log.Debugf("use Idp way")
	var scopedToken string
	if scopedToken, err = getScopedTokenByIdpToken(p.tokenFile, p.config); err != nil {
		return err
	}

	tokenAuth := hwIam.NewIamCredentialsBuilder().WithXAuthToken(scopedToken).Build()
	region := region.NewRegion(p.config.Region, fmt.Sprintf("https://dns.%s.myhuaweicloud.com", p.config.Region))
	httpClient, err := hwdns.DnsClientBuilder().
		WithRegion(region).
		WithCredential(tokenAuth).
		WithCredentialsType("v3.IamCredentials").
		WithHttpConfig(config.DefaultHttpConfig()).
		SafeBuild()
	if err != nil {
		return errors.Wrapf(err, "failed to get Huawei Cloud Client")
	}
	p.dnsClient = hwdns.NewDnsClient(httpClient)
	return
}

func parseConfig(configFile string) (*HuaweiCloudConfig, error) {
	cfg := &HuaweiCloudConfig{}
	if configFile == "" {
		return cfg, fmt.Errorf("fail to get configFile")
	}
	contents, err := os.ReadFile(configFile)
	if err != nil {
		return cfg, fmt.Errorf("failed to read Huawei Cloud config file '%s': %v", configFile, err)
	}
	err = yaml.Unmarshal(contents, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("failed to parse Huawei Cloud config file '%s': %v", configFile, err)
	}
	return cfg, nil
}

func getScopedTokenByIdpToken(tokenFile string, cfg *HuaweiCloudConfig) (scopedToken string, err error) {
	basicAuth, err := basic.NewCredentialsBuilder().
		WithIdpId(cfg.IdpID).
		WithIdTokenFile(tokenFile).
		WithProjectId(cfg.ProjectID).
		SafeBuild()
	if err != nil {
		return "", errors.Wrapf(err, "failed to get basic auth")
	}
	idToken, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read token file")
	}
	region := region.NewRegion(cfg.Region, fmt.Sprintf("https://iam.%s.myhuaweicloud.com", cfg.Region))
	iamClient := hwIam.NewIamClient(
		hwIam.IamClientBuilder().
			WithRegion(region).
			WithCredential(basicAuth).
			WithHttpConfig(config.DefaultHttpConfig()).
			Build())
	// get unscopedToken
	req := &iamMdl.CreateTokenWithIdTokenRequest{XIdpId: cfg.IdpID, Body: &iamMdl.GetIdTokenRequestBody{Auth: &iamMdl.GetIdTokenAuthParams{}}}
	req.Body.Auth.IdToken = &iamMdl.GetIdTokenIdTokenBody{Id: string(idToken)}
	idTokenResponse, err := iamClient.CreateTokenWithIdToken(req)
	if err != nil {
		return "", errors.Wrapf(err, "failed to create token with id token")
	}
	unscopedToken := *idTokenResponse.XSubjectToken

	// get scopedToken
	scopedTokenRequest := &iamMdl.KeystoneCreateScopedTokenRequest{Body: &iamMdl.KeystoneCreateScopedTokenRequestBody{Auth: &iamMdl.ScopedTokenAuth{}}}
	scopedTokenRequest.Body.Auth.Scope = &iamMdl.TokenSocpeOption{Project: &iamMdl.ScopeProjectOption{Id: &cfg.ProjectID}}
	scopedTokenRequest.Body.Auth.Identity = &iamMdl.ScopedTokenIdentity{Methods: []string{"token"}, Token: &iamMdl.ScopedToken{Id: unscopedToken}}
	scopedTokenResponse, err := iamClient.KeystoneCreateScopedToken(scopedTokenRequest)
	if err != nil {
		return "", errors.Wrapf(err, "failed to create scoped token")
	}
	scopedToken = *scopedTokenResponse.XSubjectToken
	return
}

// Records gets the current records.
//
// Returns the current records or an error if the operation failed.
func (p *HuaweicloudProvider) Records(ctx context.Context) (endpoints []*endpoint.Endpoint, err error) {
	log.Infof("Retrieving Huawei Cloud DNS Domain Records")

	if err := p.refreshToken(); err != nil {
		return nil, err
	}
	zones, err := p.getZones()
	if err != nil {
		return nil, err
	}

	zoneRecordsGroup, err := p.getZoneRecordGroup(zones)
	if err != nil {
		return nil, err
	}

	endpoints = make([]*endpoint.Endpoint, 0)
	recordMap := groupRecords(zoneRecordsGroup)
	for _, recordList := range recordMap {
		for _, record := range recordList.records {
			name := cleanDomainName(*record.Name)
			recordType := *record.Type
			ttl := *record.Ttl
			targets := *record.Records
			endpoints = append(endpoints, endpoint.NewEndpointWithTTL(name, recordType, endpoint.TTL(ttl), targets...))
		}
	}
	return endpoints, err
}

func groupRecords(zoneRecordsGroup map[string]RecordListGroup) (endpointMap map[string]RecordListGroup) {
	endpointMap = make(map[string]RecordListGroup)
	for _, recordGroup := range zoneRecordsGroup {
		for _, record := range recordGroup.records {
			key := fmt.Sprintf("%s:%s", *record.Type, *record.Name)
			m, exist := endpointMap[key]
			if !exist {
				endpointMap[key] = RecordListGroup{
					domain:  recordGroup.domain,
					records: make([]dnsMdl.ListRecordSets, 0),
				}
			}
			m.records = append(m.records, record)
			endpointMap[key] = m
		}
	}
	return endpointMap
}

// group zone and record by zone id
func (p *HuaweicloudProvider) getZoneRecordGroup(zones []dnsMdl.PrivateZoneResp) (map[string]RecordListGroup, error) {
	recordListGroup := make(map[string]RecordListGroup, 0)
	var length int
	for _, zone := range zones {
		recordSets, err := p.getZoneRecordList(*zone.Id)
		if err != nil {
			return nil, err
		}
		for _, recordSet := range recordSets {
			if *recordSet.Type == "TXT" {
				records := make([]string, 0)
				for _, record := range *recordSet.Records {
					record := p.unescapeTXTRecordValue(record)
					records = append(records, record)
				}
				recordSet.Records = &records
			}
		}
		recordListGroup[*zone.Id] = RecordListGroup{
			domain:  zone,
			records: recordSets,
		}
		length += len(recordSets)
	}
	log.Infof("Found %d Huawei Cloud DNS record(s).", length)
	return recordListGroup, nil
}

func (p *HuaweicloudProvider) unescapeTXTRecordValue(value string) string {
	if strings.HasPrefix(value, "heritage=") {
		return fmt.Sprintf("\"%s\"", strings.Replace(value, ";", ",", -1))
	}
	return value
}

// getZones returns the list of hosted zones.
func (p *HuaweicloudProvider) getZones() ([]dnsMdl.PrivateZoneResp, error) {
	zones := make([]dnsMdl.PrivateZoneResp, 0)

	req := &dnsMdl.ListPrivateZonesRequest{}
	req.Offset = int32Ptr(0)
	req.Limit = int32Ptr(50)
	totalCount := int32(50)
	if p.privateZone {
		req.Type = "private"
	}

	for *req.Offset < totalCount {
		resp, err := p.dnsClient.ListPrivateZones(req)
		if err != nil {
			return nil, errors.Wrap(err, "failed to list zones for Huawei Cloud DNS")
		}
		for _, zone := range *resp.Zones {
			if p.domainFilter.IsConfigured() {
				if !p.domainFilter.Match(*zone.Name) {
					if !p.zoneMatchParent {
						continue
					}
					if !p.domainFilter.MatchParent(*zone.Name) {
						continue
					}
				}
			}

			if p.zoneIDFilter.IsConfigured() {
				if !p.zoneIDFilter.Match(*zone.Id) {
					continue
				}
			}

			if p.privateZone {
				if !p.matchVPC(*zone.Id) {
					continue
				}
			}

			zones = append(zones, zone)
		}
		totalCount = *resp.Metadata.TotalCount
		req.Offset = int32Ptr(*req.Offset + int32(len(*resp.Zones)))
	}
	return zones, nil
}

// matchVPC queries the VPC by zoneId and checks if it matches
func (p *HuaweicloudProvider) matchVPC(zoneId string) bool {
	// if VPC is empty, skip the check
	if p.vpcID == "" {
		return true
	}
	m := &dnsMdl.ShowPrivateZoneRequest{}
	m.ZoneId = zoneId
	resp, err := p.dnsClient.ShowPrivateZone(m)
	if err != nil {
		return false
	}
	foundVPC := false
	for _, vpc := range *resp.Routers {
		if vpc.RouterId == p.vpcID {
			foundVPC = true
			break
		}
	}
	return foundVPC
}

// getZoneRecordList return list of records for a given zone id
func (p *HuaweicloudProvider) getZoneRecordList(zoneId string) ([]dnsMdl.ListRecordSets, error) {
	req := &dnsMdl.ListRecordSetsByZoneRequest{}
	req.ZoneId = zoneId
	req.Offset = int32Ptr(0)
	req.Limit = int32Ptr(50)
	totalCount := int32(50)

	recordList := make([]dnsMdl.ListRecordSets, 0)
	for *req.Offset < totalCount {
		resp, err := p.dnsClient.ListRecordSetsByZone(req)
		if err != nil {
			return nil, errors.Wrap(err, "fail to list records for Huawei Cloud DNS")
		}

		for _, recordSet := range *resp.Recordsets {
			if !provider.SupportedRecordType(*recordSet.Type) {
				continue
			}
			if *recordSet.Default {
				continue
			}
			recordList = append(recordList, recordSet)
		}

		totalCount = *resp.Metadata.TotalCount
		req.Offset = int32Ptr(*req.Offset + int32(len(*resp.Recordsets)))
	}
	return recordList, nil
}

// equalStringSlice determines if two slices of strings are equal
func equalStringSlice(a, b []string) bool {
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}

	if (a == nil) != (b == nil) {
		return false
	}

	for i, _ := range a {
		a[i] = strings.TrimSuffix(a[i], ".")
		b[i] = strings.TrimSuffix(b[i], ".")
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func JsonWrapper(obj interface{}) string {
	if jsonStr, jsonErr := json.Marshal(obj); jsonErr == nil {
		return string(jsonStr)
	}
	return "json_format_error"
}

// cleanDomainName removes the "." suffix
func cleanDomainName(domain string) string {
	return strings.TrimSuffix(domain, ".")
}

// ApplyChanges applies the given changes.
//
// Returns nil if the operation was successful or an error if the operation failed.
func (p *HuaweicloudProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if !changes.HasChanges() {
		return nil
	}
	log.Infof("apply changes. %s", JsonWrapper(changes))

	if err := p.refreshToken(); err != nil {
		return err
	}

	zones, err := p.getZones()
	if err != nil {
		return err
	}
	zoneNameIdMap := make(map[string][]string)
	if p.privateZone && p.vpcID == "" {
		// handle private zones with the same name
		for _, zone := range zones {
			if _, exist := zoneNameIdMap[*zone.Name]; !exist {
				zoneNameIdMap[*zone.Name] = make([]string, 0)
			}
			zoneNameIdMap[*zone.Name] = append(zoneNameIdMap[*zone.Name], *zone.Id)
		}
	}

	zoneRecordsGroup, err := p.getZoneRecordGroup(zones)
	if err != nil {
		return err
	}
	if p.privateZone && p.vpcID == "" {
		log.Info("Check Huawei Cloud DNS private zone name")
		for name, ids := range zoneNameIdMap {
			if len(ids) > 1 {
				for _, id := range ids {
					delete(zoneRecordsGroup, id)
				}
				log.Errorf("Conflict: Multiple zones with same name %v,Skip it", name)
			}
		}
	}

	zoneNameIDMapper := provider.ZoneIDName{}
	for _, recordsListGroup := range zoneRecordsGroup {
		if *recordsListGroup.domain.Id != "" {
			zoneNameIDMapper.Add(*recordsListGroup.domain.Id, cleanDomainName(*recordsListGroup.domain.Name))
		}
	}

	deleteChanges := append(changes.Delete, changes.UpdateOld...)
	deleteEndpoints := p.getDeleteRecordIdsMap(zoneNameIDMapper, deleteChanges, zoneRecordsGroup)
	var failedZones []string
	failedDeleteZones := p.deleteRecords(deleteEndpoints)
	failedZones = append(failedZones, failedDeleteZones...)

	createEndpoints := make(map[string][]*endpoint.Endpoint)
	createChanges := append(changes.Create, changes.UpdateNew...)
	for _, createChange := range createChanges {
		zoneId, _ := zoneNameIDMapper.FindZone(cleanDomainName(createChange.DNSName))
		if zoneId != "" {
			if _, exist := createEndpoints[zoneId]; !exist {
				createEndpoints[zoneId] = make([]*endpoint.Endpoint, 0)
			}
			createEndpoints[zoneId] = append(createEndpoints[zoneId], createChange)
		} else {
			log.Infof("Missing domain name for creating %v record %v", createChange.RecordType, createChange.DNSName)
		}
	}
	failedCreateZones := p.createRecords(createEndpoints)
	set := make(map[string]struct{})
	for _, zone := range failedZones {
		set[zone] = struct{}{}
	}
	for _, zone := range failedCreateZones {
		if _, exist := set[zone]; !exist {
			failedZones = append(failedZones, zone)
		}
	}
	if len(failedZones) > 0 {
		return provider.NewSoftError(fmt.Errorf("failed to submit all chances for the following zones: %v", failedZones))
	}
	return err
}

func (p *HuaweicloudProvider) getDeleteRecordIdsMap(zoneNameIDMapper provider.ZoneIDName, changes []*endpoint.Endpoint, domainRecordsGroup map[string]RecordListGroup) map[string][]string {
	deleteEndpoints := make(map[string][]string)
	for _, deleteChange := range changes {
		if zoneId, _ := zoneNameIDMapper.FindZone(cleanDomainName(deleteChange.DNSName)); zoneId != "" {
			recordListGroup := domainRecordsGroup[zoneId]

			for _, record := range recordListGroup.records {
				if cleanDomainName(*record.Name) == cleanDomainName(deleteChange.DNSName) && *record.Type == deleteChange.RecordType {
					if equalStringSlice(*record.Records, deleteChange.Targets) {
						if _, exist := deleteEndpoints[zoneId]; !exist {
							deleteEndpoints[zoneId] = make([]string, 0)
						}
						deleteEndpoints[zoneId] = append(deleteEndpoints[zoneId], *record.Id)
					}
				}
			}
		}
	}
	return deleteEndpoints
}

func (p *HuaweicloudProvider) createRecords(endpointsMap map[string][]*endpoint.Endpoint) (failedZones []string) {
	for zoneId, endpoints := range endpointsMap {
		err := p.createRecordByZoneId(zoneId, endpoints)
		if err != nil {
			failedZones = append(failedZones, zoneId)
		}
	}
	return
}

func (p *HuaweicloudProvider) createRecordByZoneId(zoneId string, endpoints []*endpoint.Endpoint) error {
	for _, endpoint := range endpoints {
		req := &dnsMdl.CreateRecordSetRequest{}
		req.Body = &dnsMdl.CreateRecordSetRequestBody{}
		req.ZoneId = zoneId
		req.Body.Name = endpoint.DNSName
		req.Body.Type = endpoint.RecordType
		req.Body.Records = endpoint.Targets
		if endpoint.RecordTTL.IsConfigured() {
			req.Body.Ttl = int32Ptr(int32(endpoint.RecordTTL))
		}
		if p.dryRun {
			log.Infof("Dry run: Create %s record named '%s' to '%s' with ttl %d for Huawei Cloud DNS", endpoint.RecordType, endpoint.DNSName, endpoint.Targets, endpoint.RecordTTL)
			continue
		}
		response, err := p.dnsClient.CreateRecordSet(req)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to create record %s for Huawei Cloud DNS", endpoint.DNSName))
			return err
		} else {
			log.Infof("Create %s record named '%s' to '%s' with ttl %d for Huawei Cloud DNS: Record ID=%s", endpoint.RecordType, endpoint.DNSName, endpoint.Targets.String(), endpoint.RecordTTL, *response.Id)
		}
	}
	return nil
}

func (p *HuaweicloudProvider) deleteRecords(recordIdsMap map[string][]string) (failedZones []string) {
	for zoneId, recordIds := range recordIdsMap {
		err := p.deleteRecordsByZoneId(zoneId, recordIds)
		if err != nil {
			failedZones = append(failedZones, zoneId)
		}
	}
	return failedZones
}

func (p *HuaweicloudProvider) deleteRecordsByZoneId(zoneId string, recordIds []string) error {
	if len(recordIds) == 0 {
		return nil
	}
	for _, recordId := range recordIds {
		if p.dryRun {
			log.Infof("Dry run: Delete record id '%s' in Huawei Cloud DNS", recordId)
			continue
		}
		req := &dnsMdl.DeleteRecordSetRequest{}
		req.ZoneId = zoneId
		req.RecordsetId = recordId
		response, err := p.dnsClient.DeleteRecordSet(req)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to delete record %s in Huawei Cloud DNS", recordId))
			return err
		} else {
			log.Infof("Delete record id %s in Huawei Cloud DNS", *response.Id)
		}
	}
	return nil
}

func int32Ptr(v int32) *int32 {
	return &v
}
