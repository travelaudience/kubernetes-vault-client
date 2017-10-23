package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/travelaudience/kubernetes-vault-client/pkg/config"
	"golang.org/x/oauth2/google"
	iam "google.golang.org/api/iam/v1"
)

const (
	tokenValidity = 1 * time.Minute
)

type IamAuthenticator struct {
	cfg       *config.IamAuthConfig
	iamClient *iam.Service
}

func NewIamAuthenticator(c *config.IamAuthConfig) *IamAuthenticator {
	return &IamAuthenticator{cfg: c}
}

func (a *IamAuthenticator) Init() error {
	credsBytes, err := ioutil.ReadFile(a.cfg.SigningServiceAccountKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read the credentials file: %v", err)
	}
	iamcfg, err := google.JWTConfigFromJSON(credsBytes, iam.CloudPlatformScope)
	if err != nil {
		return fmt.Errorf("failed to generate JWT configuration: %v", err)
	}
	iamClient, err := iam.New(iamcfg.Client(context.Background()))
	if err != nil {
		return fmt.Errorf("failed to create Cloud IAM client: %v", err)
	}
	a.iamClient = iamClient
	return nil
}

func (a *IamAuthenticator) GetRole() string {
	return a.cfg.Role
}

func (a *IamAuthenticator) GetToken() (string, error) {
	name := "projects/-/serviceAccounts/" + a.cfg.ServiceAccountID

	jwtPayload := map[string]interface{}{
		"aud": "vault/" + a.cfg.Role,
		"sub": a.cfg.ServiceAccountID,
		"exp": time.Now().Add(tokenValidity).Unix(),
	}

	payloadBytes, err := json.Marshal(jwtPayload)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req := &iam.SignJwtRequest{
		Payload: string(payloadBytes),
	}

	res, err := a.iamClient.Projects.ServiceAccounts.SignJwt(name, req).Do()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %v", err)
	}

	return res.SignedJwt, nil
}
