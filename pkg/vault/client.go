package vault

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"github.com/travelaudience/kubernetes-vault-client/pkg/config"
	"github.com/travelaudience/kubernetes-vault-client/pkg/debug"
	"github.com/travelaudience/kubernetes-vault-client/pkg/vault/auth"
	"github.com/travelaudience/kubernetes-vault-client/pkg/vault/auth/iam"
	"github.com/travelaudience/kubernetes-vault-client/pkg/vault/auth/kubernetes"
)

const (
	pathToLogin        = "auth/%s/login"
	renewerGracePeriod = 3 * time.Second
)

const (
	PKIIssueCertificateCertKey       = "certificate"
	PKIIssueCertificateCAChainKey    = "ca_chain"
	PKIIssueCertificatePrivateKeyKey = "private_key"
)

type VaultClient struct {
	client   *vaultapi.Client
	secret   *vaultapi.Secret
	RenewErr chan error
}

func NewClient(cfg *config.Config) (*VaultClient, error) {
	// Check whether the configuration is valid.
	if err := cfg.Check(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	var authenticator auth.VaultAuthenticator

	// Check which type of authentication we are using and create the
	// corresponding authenticator.
	switch cfg.Auth.Type {
	case config.IamAuthType:
		data := cfg.Auth.Data.(config.IamAuthConfig)
		authenticator = iam.NewIamAuthenticator(&data)
	case config.KubernetesAuthType:
		data := cfg.Auth.Data.(config.KubernetesAuthConfig)
		authenticator = kubernetes.NewKubernetesAuthenticator(&data)
	default:
		// Shouldn't be reached.
		return nil, fmt.Errorf("unknown auth type '%s'", cfg.Auth.Type)
	}

	log.Debug("vault: auth started")

	// Initialize the authenticator.
	if err := authenticator.Init(); err != nil {
		return nil, err
	}

	// Get a token from the authenticator.
	jwt, err := authenticator.GetToken()
	if err != nil {
		return nil, err
	}
	log.Debugf("authenticator: token:\n\n%s\n", jwt)

	// Create the underlying Vault API client.
	client, err := vaultapi.NewClient(&vaultapi.Config{Address: cfg.Address})
	if err != nil {
		return nil, err
	}

	// Authenticate with the GCP backend.
	secret, err := client.Logical().Write(
		fmt.Sprintf(pathToLogin, cfg.Auth.Backend),
		map[string]interface{}{
			"jwt":  jwt,
			"role": authenticator.GetRole(),
		},
	)
	if err != nil {
		return nil, err
	}
	log.Debugf("vault: auth response:\n\n%s\n", debug.PrettyPrint(secret))

	// Create the resulting client.
	result := &VaultClient{
		client:   client,
		secret:   secret,
		RenewErr: make(chan error, 1),
	}

	// Start the token renew process.
	go result.renewToken(secret.Auth.ClientToken, secret.Auth.Accessor)
	// Set the Vault client token.
	result.client.SetToken(secret.Auth.ClientToken)

	authLogger(secret).Info("vault: auth successful")

	// Return the client.
	return result, nil
}

func (c *VaultClient) GetAccessor() string {
	return c.secret.Auth.Accessor
}

func (c *VaultClient) GetToken() string {
	return c.secret.Auth.ClientToken
}

func (c *VaultClient) GetKV(path string) (map[string]string, error) {
	sec, err := c.client.Logical().Read(path)
	if err != nil {
		return nil, err
	}
	if sec == nil {
		return nil, fmt.Errorf("vault: nothing found at %s", path)
	}

	res := make(map[string]string)

	for k, v := range sec.Data {
		switch val := v.(type) {
		case string:
			res[k] = val
		default:
			return nil, fmt.Errorf("vault: %s[%s] has type %T", path, k, val)
		}
	}

	return res, nil
}

func (c *VaultClient) GetPKI(mount, role, cn string, sans []string, cnIsIdentifier bool) (map[string]string, error) {
	var (
		ips   []string
		names []string
	)

	for _, val := range sans {
		if addr := net.ParseIP(val); addr != nil {
			ips = append(ips, addr.String())
		} else {
			names = append(names, val)
		}
	}

	path := mount + "/issue/" + role

	sec, err := c.client.Logical().Write(
		path,
		map[string]interface{}{
			"common_name":          cn,
			"alt_names":            strings.Join(names, ","),
			"ip_sans":              strings.Join(ips, ","),
			"exclude_cn_from_sans": cnIsIdentifier,
		},
	)
	if err != nil {
		return nil, err
	}
	if sec == nil {
		return nil, fmt.Errorf("vault: unexpected nil response from %s", path)
	}

	res := make(map[string]string)

	for k, v := range sec.Data {
		switch val := v.(type) {
		case string:
			res[k] = val
		case []interface{}:
			res[k] = ""
			for i, e := range val {
				switch nvl := e.(type) {
				case string:
					res[k] = res[k] + "\n" + nvl
				default:
					return nil, fmt.Errorf("vault: %s[%d] has type %T", k, i, val)
				}
			}
		default:
			return nil, fmt.Errorf("vault: %s has type %T", k, val)
		}
	}

	return res, nil
}

func (c *VaultClient) renewToken(token, accessor string) {
	// Grab the freshest authentication secret.
	secret, err := c.client.Auth().Token().RenewTokenAsSelf(token, 0)
	if err != nil {
		c.RenewErr <- err
	}

	// Create a new Renewer for the secret, with a grace period of
	// renewerGracePeriod. This means that the renewer will stop when the
	// remaining lease duration is less than renewerGracePeriod.
	//
	// For example, if the requested role in the 'gcp' backend is configured
	// with ttl="60s" and max_ttl="90s", a few renewals will be made before
	// renewer.DoneCh() is sent the nil value. On the other hand, if max_ttl is
	// not defined then renewer.DoneCh() will be sent at most a single error
	// (when and if it occurrs).
	renewer, err := c.client.NewRenewer(&vaultapi.RenewerInput{
		Grace:  renewerGracePeriod,
		Secret: secret,
	})
	if err != nil {
		c.RenewErr <- err
	}

	// Start the renewing process.
	go renewer.Renew()
	// Stop the renewing process and free resources.
	defer renewer.Stop()

loop:
	for {
		select {
		case err := <-renewer.DoneCh():
			if err != nil {
				c.RenewErr <- err
				break loop
			} else {
				c.RenewErr <- errors.New("vault: auth token cannot be renewed")
				break loop
			}
		case res := <-renewer.RenewCh():
			if res != nil && res.Secret != nil && res.Secret.Auth != nil {
				sec := res.Secret
				authLogger(sec).Infof("vault: auth token renewed")
			} else {
				c.RenewErr <- errors.New("vault: renew: no auth data")
				break loop
			}
		}
	}
}

func authLogger(secret *vaultapi.Secret) *log.Entry {
	return log.WithFields(log.Fields{
		"token_accessor": secret.Auth.Accessor,
		"token_ttl_sec":  secret.Auth.LeaseDuration,
	})
}
