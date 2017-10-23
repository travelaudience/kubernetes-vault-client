package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"reflect"

	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	"github.com/travelaudience/kubernetes-vault-client/pkg/debug"
	yaml "gopkg.in/yaml.v2"
)

const (
	// IamAuthType represents the "iam" authentication type as defined in
	// https://www.vaultproject.io/docs/auth/gcp.html
	IamAuthType = "iam"
	// KubernetesAuthType represents the "kubernetes" authentication type as
	// defined in https://www.vaultproject.io/docs/auth/kubernetes.html
	KubernetesAuthType = "kubernetes"
)

const (
	// InitCModeName represents the "initC" mode. In this mode the app dumps a
	// list of secrets into specified paths and exits.
	InitCModeName = "initC"
)

var (
	authTypes = map[string]bool{
		IamAuthType:        true,
		KubernetesAuthType: true,
	}
	authTypeKeys = reflect.ValueOf(authTypes).MapKeys()
)

var (
	modeNames = map[string]bool{
		InitCModeName: true,
	}
	modeNameKeys = reflect.ValueOf(modeNames).MapKeys()
)

// AuthConfig represents authentication data.
type AuthConfig struct {
	// Backend is the path where the GCP or Kubernetes auth backends are
	// mounted. For example, if the plugin was enabled using
	//
	// vault auth-enable -path 'my-gcp-backend' gcp
	//
	// then Backend must be 'my-gcp-backend'.
	Backend string `json:"backend"`
	// Data is the authentication data itself.
	Data interface{} `json:"data"`
	// Type is the authentication type being used ("iam" or "kubernetes").
	Type string `json:"type"`
}

// KubernetesAuthConfig carries authentication data for the "kubernetes" auth
// method.
type KubernetesAuthConfig struct {
	// Role is the Vault role being requested.
	Role string `json:"role"`
}

// IamAuthConfig carries authentication data for the "iam" auth method.
type IamAuthConfig struct {
	// Role is the Vault role being requested.
	Role string `json:"role"`
	// ServiceAccountID is the ID of the service account which authenticates
	// with Vault.
	ServiceAccountID string `json:"serviceAccountId"`
	// SigningServiceAccountKeyPath is the path to a JSON file containing
	// the credentials of the service account that will sign JWT tokens for
	// the ServiceAccountID account.
	SigningServiceAccountKeyPath string `json:"signingServiceAccountKeyPath"`
}

// Config represents the application's configuration.
type Config struct {
	// Address is the address where Vault can be reached.
	Address string `json:"address"`
	// Auth is the configuration for authentication.
	Auth AuthConfig `json:"auth"`
	// Debug indicates whether debugging is enabled.
	Debug bool `json:"-" yaml:"-"`
	// Mode is the configuration for the app's 'modus operandi'.
	Mode ModeConfig `json:"mode"`
	// TargetURL is the parsed version of Address.
	TargetURL *url.URL `json:"-" yaml:"-"`
}

// ModeConfig represents the app's 'modus operandi'.
type ModeConfig struct {
	// Data is the configuration for the chosen mode.
	Data interface{} `json:"data"`
	// Name is the name of the mode in use (only "initC" is supported for now).
	Name string `json:"name"`
}

// InitCModeConfig represents the configuration for the "initC" mode.
type InitCModeConfig struct {
	// KV is the list of secret requests from Vault.
	KV []KVRequest `json:"kv"`
	// PKI is the list of PKI requests from Vault.
	PKI []PKIRequest `json:"pki"`
}

// KVRequest represents a request for a key from a given Vault path.
type KVRequest struct {
	// Path is the path to the secret in Vault (e.g., secrets/foo).
	Path string `json:"path"`
	// Key is the requested key.
	Key string `json:"key"`
	// MountPath is the path where the requested secret will be mounted.
	MountPath string `json:"mountPath"`
}

// PKIRequest represents a request for a certificate from Vault's PKI backend.
type PKIRequest struct {
	// MountName is the name of the PKI mount in Vault (e.g., 'pki').
	MountName string `json:"mountName"`
	// RoleName is the name of the role configured in Vault's PKI mount.
	RoleName string `json:"role"`
	// CN is the "common name" being requested for the certificate.
	CN string `json:"cn"`
	// SANs is a list of additional DNS names or IP addresses being requested.
	SANs []string `json:"sans"`
	// CNIsIdentifier indicates whether the requested CN is an identifier rather
	// than an hostname (e.g. 'kube-admin' instead of 'vault.example.com').
	CNIsIdentifier bool `json:"cnIsIdentifier"`
	// MountDir is the directory where the requested certificate and
	// private key will be mounted.
	MountDir string `json:"mountDir"`
}

// Check determines whether the specified Config is valid.
func (cfg *Config) Check() error {
	u := cfg.TargetURL

	switch u.Scheme {
	case "http":
		log.Warn("potentially insecure address specified for vault")
	case "https":
		// All is well.
	default:
		return errors.New("address must be an http or (preferably) https url")
	}
	if u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("address must be http[s]://host[:port][/path]")
	}
	if cfg.Auth.Backend == "" {
		return errors.New("must specify the path to the the gcp auth backend")
	}

	switch cfg.Auth.Type {
	case IamAuthType:
		data := cfg.Auth.Data.(IamAuthConfig)
		if data.SigningServiceAccountKeyPath == "" {
			return errors.New("must specify a path to the service account key")
		}
		if data.Role == "" {
			return errors.New("must specify a role to request")
		}
		if data.ServiceAccountID == "" {
			return errors.New("must specify a service account id")
		}
	case KubernetesAuthType:
		data := cfg.Auth.Data.(KubernetesAuthConfig)
		if data.Role == "" {
			return errors.New("must specify a role to request")
		}
	default:
		// Should never happen.
		return fmt.Errorf("auth.type must be one of %v", authTypes)
	}

	switch cfg.Mode.Name {
	case InitCModeName:
		data := cfg.Mode.Data.(InitCModeConfig)
		for _, val := range data.KV {
			if val.Path == "" {
				return fmt.Errorf("must specify the path to a secret")
			}
			if val.Key == "" {
				return fmt.Errorf("must specify a key to request")
			}
			if !filepath.IsAbs(val.MountPath) {
				return fmt.Errorf("path must be absolute: %v", val.MountPath)
			}
		}
		for _, val := range data.PKI {
			if val.MountName == "" {
				return fmt.Errorf("must specify a mount name (e.g., 'pki')")
			}
			if val.RoleName == "" {
				return fmt.Errorf("must specify a role name")
			}
			if val.CN == "" {
				return fmt.Errorf("must specifiy a cn for the certificate")
			}
			if !filepath.IsAbs(val.MountDir) {
				return fmt.Errorf("path must be absolute: %v", val.MountDir)
			}
		}
	default:
		// Should never happen.
		return fmt.Errorf("mode must be one of %v", modeNames)
	}

	log.Debug("config: seems ok")

	return nil
}

// Parse attempts to parse the configuration file at the specified path.
func Parse(path string) (*Config, error) {
	// Try to read data from the specified configuration file.
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Create an empty 'Config' structure where to dump configuration to.
	cfg := &Config{}

	// Try to unmarshal the configuration file into 'cfg'.
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Parse the specified value of 'address' as a URL, as this will be needed
	// later.
	addr, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, err
	}
	cfg.TargetURL = addr

	// Decode map data in 'cfg.Auth.Data' into one of 'IamAuthConfig' or
	// 'KubernetesAuthConfig'.
	switch cfg.Auth.Type {
	case IamAuthType:
		res := IamAuthConfig{}
		if err := mapstructure.Decode(cfg.Auth.Data, &res); err != nil {
			return nil, err
		}
		cfg.Auth.Data = res
	case KubernetesAuthType:
		res := KubernetesAuthConfig{}
		if err := mapstructure.Decode(cfg.Auth.Data, &res); err != nil {
			return nil, err
		}
		cfg.Auth.Data = res
	default:
		return nil, fmt.Errorf("auth.type must be one of %v", authTypeKeys)
	}

	// Decode map data in 'cfg.Mode.Data' into one of the supported mode
	// configurations.
	switch cfg.Mode.Name {
	case InitCModeName:
		res := InitCModeConfig{}
		if err := mapstructure.Decode(cfg.Mode.Data, &res); err != nil {
			return nil, err
		}
		cfg.Mode.Data = res
	default:
		return nil, fmt.Errorf("mode.name must be one of %v", modeNameKeys)
	}

	log.Debugf("config: parsing ok\n\n%s\n", debug.PrettyPrint(*cfg))

	return cfg, nil
}
