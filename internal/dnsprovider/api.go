/*
Copyright 2017 The Kubernetes Authors.

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

import "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/model"

// HuaweiCloudDNSAPI is the subset of the HuaweiCloud DNS API that we actually use.  Add methods as required. Signatures must match exactly.
type HuaweiCloudDNSAPI interface {
	CreateRecordSet(request *model.CreateRecordSetRequest) (*model.CreateRecordSetResponse, error)
	DeleteRecordSet(request *model.DeleteRecordSetRequest) (*model.DeleteRecordSetResponse, error)
	ListRecordSetsByZone(request *model.ListRecordSetsByZoneRequest) (*model.ListRecordSetsByZoneResponse, error)
	ShowPrivateZone(request *model.ShowPrivateZoneRequest) (*model.ShowPrivateZoneResponse, error)
	ListPrivateZones(request *model.ListPrivateZonesRequest) (*model.ListPrivateZonesResponse, error)
}
