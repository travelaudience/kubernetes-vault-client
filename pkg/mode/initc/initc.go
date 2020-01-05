package initc

import (
	"context"
	"fmt"
	"path"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"github.com/travelaudience/kubernetes-vault-client/pkg/config"
	"github.com/travelaudience/kubernetes-vault-client/pkg/mode"
	"github.com/travelaudience/kubernetes-vault-client/pkg/util/fs"
	"github.com/travelaudience/kubernetes-vault-client/pkg/vault"
)

const (
	fnCert  = "crt.pem"
	fnKey   = "key.pem"
	fnChain = "chain.pem"
)

func Run(ctx context.Context, cfg *config.InitCModeConfig) {
	client := ctx.Value(mode.Client).(*vault.VaultClient)

	// Dump the secrets.
	if err := dumpSecrets(cfg, client); err != nil {
		log.Fatalf("failed to dump secrets: %v", err)
	}

	// Dump the certificates.
	if err := dumpCertificates(cfg, client); err != nil {
		log.Fatalf("failed to dump certificates: %v", err)
	}

	// Log and exit.
	log.Info("initC: dump successful")
}

func dumpSecrets(cfg *config.InitCModeConfig, client *vault.VaultClient) error {
	// Grab a map of the Vault paths we need to visit.
	paths := make(map[string]bool)

	// Add paths to the map.
	for _, kvr := range cfg.KV {
		paths[kvr.Path] = true
	}

	// Grab a map in which to store each secret's data.
	secs := make(map[string]map[string]string)

	// Grab an error accumulator for Vault API errors.
	var vErrs *multierror.Error

	// Grab each secret from Vault.
	for p := range paths {
		if sec, err := client.GetKV(p); err != nil {
			vErrs = multierror.Append(vErrs, err)
		} else {
			secs[p] = sec
		}
	}

	// Return if there have been any errors while reading from Vault.
	if err := vErrs.ErrorOrNil(); err != nil {
		return err
	}

	// Grab an error accumulator for non-existing keys.
	var kErrs *multierror.Error

	// Check for requested keys that do not exist at the specified paths.
	for _, kvr := range cfg.KV {
		// skipping if all specified
		if kvr.Key == "*" {
			continue
		}

		if sec := secs[kvr.Path][kvr.Key]; sec == "" {
			kErrs = multierror.Append(kErrs, fmt.Errorf("'%s' doesn't exist at '%s'", kvr.Key, kvr.Path))
		}
	}

	// Return if any of the requested keys does not exist.
	if err := kErrs.ErrorOrNil(); err != nil {
		return err
	}

	// Grab an error accumulator for dumping errors.
	var dErrs *multierror.Error

	// Dump each key to the specified mount path.
	for _, kvr := range cfg.KV {
		// mount them all
		if kvr.Key == "*" {
			for secKey, secValue := range secs[kvr.Path] {
				mountPath := kvr.MountPath + "/" + secKey
				if err := fs.Write(mountPath, secValue); err != nil {
					dErrs = multierror.Append(dErrs, err)
					break
				}
			}
			continue
		}

		if err := fs.Write(kvr.MountPath, secs[kvr.Path][kvr.Key]); err != nil {
			dErrs = multierror.Append(dErrs, err)
		}
	}

	// Return an error iif there have been any errors while writing secrets.
	return dErrs.ErrorOrNil()
}

func dumpCertificates(cfg *config.InitCModeConfig, client *vault.VaultClient) error {
	// Grab a map in which to store each secret's data.
	certs := make([]map[string]interface{}, 0)
	// Grab an error accumulator for Vault API errors.
	var vErrs *multierror.Error

	// Grab each certificate from Vault.
	for _, r := range cfg.PKI {
		if sec, err := client.GetPKI(r.MountName, r.Role, r.CN, r.SANs, r.CNIsIdentifier); err != nil {
			vErrs = multierror.Append(vErrs, err)
		} else {
			certs = append(certs, map[string]interface{}{
				"dir": r.MountDir,
				"crt": sec,
			})
		}
	}

	// Return if there have been any errors while reading from Vault.
	if err := vErrs.ErrorOrNil(); err != nil {
		return err
	}

	// Grab an error accumulator for dumping errors.
	var dErrs *multierror.Error

	// Dump each certificate's data to the specified path.
	for _, c := range certs {
		dir := c["dir"].(string)
		crt := c["crt"].(map[string]string)

		if err := fs.Write(path.Join(dir, fnCert), crt[vault.PKIIssueCertificateCertKey]); err != nil {
			dErrs = multierror.Append(dErrs, err)
		}
		if err := fs.Write(path.Join(dir, fnKey), crt[vault.PKIIssueCertificatePrivateKeyKey]); err != nil {
			dErrs = multierror.Append(dErrs, err)
		}
		if err := fs.Write(path.Join(dir, fnChain), crt[vault.PKIIssueCertificateCAChainKey]); err != nil {
			dErrs = multierror.Append(dErrs, err)
		}
	}

	// Return an error iif there have been any errors while writing certificates.
	return dErrs.ErrorOrNil()
}
