package auth

// VaultAuthenticator must be implemented by authenticators.
type VaultAuthenticator interface {
	// Init allows for the authenticator to initialize itself.
	Init() error
	// GetRole returns the role being requested by the authenticator.
	GetRole() string
	// GetToken retrieves a signed, trusted token that can be used with the
	// Vault GCP auth plugin. It may either be an IAM service account's signed
	// JWT or a Kubernetes service account token.
	GetToken() (string, error)
}
