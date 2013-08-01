// The sts package provides types and functions for interaction with the AWS
// Security Token Service (STS).
package sts

import (
	"encoding/xml"
	"launchpad.net/goamz/aws"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// The IAM type encapsulates operations operations with the IAM endpoint.
type STS struct {
	aws.Auth
	aws.Region
}

// New creates a new IAM instance.
func New(auth aws.Auth, region aws.Region) *STS {
	return &STS{auth, region}
}

func (sts *STS) query(params map[string]string, resp interface{}) error {
	params["Version"] = "2011-06-15"
	params["Timestamp"] = time.Now().In(time.UTC).Format(time.RFC3339)
	endpoint, err := url.Parse(sts.STSEndpoint)
	if err != nil {
		return err
	}
	sign(sts.Auth, "GET", "/", params, endpoint.Host)
	endpoint.RawQuery = multimap(params).Encode()
	r, err := http.Get(endpoint.String())
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode > 200 {
		return buildError(r)
	}
	return xml.NewDecoder(r.Body).Decode(resp)
}

func buildError(r *http.Response) error {
	var (
		err    Error
		errors xmlErrors
	)
	xml.NewDecoder(r.Body).Decode(&errors)
	if len(errors.Errors) > 0 {
		err = errors.Errors[0]
	}
	err.StatusCode = r.StatusCode
	if err.Message == "" {
		err.Message = r.Status
	}
	return &err
}

func multimap(p map[string]string) url.Values {
	q := make(url.Values, len(p))
	for k, v := range p {
		q[k] = []string{v}
	}
	return q
}

func (sts *STS) GetFederationToken(duration int, name, policy string) (*GetFederationTokenResp, error) {
	params := map[string]string{
		"Action":          "GetFederationToken",
		"DurationSeconds": strconv.FormatInt(int64(duration), 10),
		"Name":            name,
		"Policy":          policy,
	}
	resp := new(GetFederationTokenResp)
	if err := sts.query(params, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type GetFederationTokenResp struct {
	RequestId        string        `xml:"ResponseMetadata>RequestId"`
	Credentials      Credentials   `xml:"GetFederationTokenResult>Credentials"`
	FederatedUser    FederatedUser `xml:"GetFederationTokenResult>FederatedUser"`
	PackedPolicySize int           `xml:"GetFederationTokenResult>PackedPolicySize"`
}

type Credentials struct {
	AccessKeyId     string    `xml:"AccessKeyId"`
	SecretAccessKey string    `xml:"SecretAccessKey"`
	SessionToken    string    `xml:"SessionToken"`
	Expiration      time.Time `xml:"Expiration"`
}

func (c Credentials) Auth() aws.Auth {
	return aws.Auth{c.AccessKeyId, c.SecretAccessKey, c.SessionToken}
}

type FederatedUser struct {
	Arn             string `xml:"Arn"`
	FederatedUserId string `xml:"FederatedUserId"`
}

type SimpleResp struct {
	RequestId string `xml:"ResponseMetadata>RequestId"`
}

type xmlErrors struct {
	Errors []Error `xml:"Error"`
}

// Error encapsulates an IAM error.
type Error struct {
	// HTTP status code of the error.
	StatusCode int

	// AWS code of the error.
	Code string

	// Message explaining the error.
	Message string
}

func (e *Error) Error() string {
	var prefix string
	if e.Code != "" {
		prefix = e.Code + ": "
	}
	if prefix == "" && e.StatusCode > 0 {
		prefix = strconv.Itoa(e.StatusCode) + ": "
	}
	return prefix + e.Message
}
