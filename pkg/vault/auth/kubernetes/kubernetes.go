package kubernetes

import (
	"io/ioutil"
	"strings"

	"github.com/travelaudience/kubernetes-vault-client/pkg/config"
)

const (
	pathToToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

type KubernetesAuthenticator struct {
	cfg *config.KubernetesAuthConfig
}

func NewKubernetesAuthenticator(c *config.KubernetesAuthConfig) *KubernetesAuthenticator {
	return &KubernetesAuthenticator{cfg: c}
}

func (a *KubernetesAuthenticator) Init() error {
	return nil
}

func (a *KubernetesAuthenticator) GetRole() string {
	return a.cfg.Role
}

func (a *KubernetesAuthenticator) GetToken() (string, error) {
	bytes, err := ioutil.ReadFile(pathToToken)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes)), nil
}
