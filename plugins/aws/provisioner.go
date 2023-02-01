package aws

import (
	"context"
	"log"
	"strings"

	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/provision"
	"github.com/Versent/saml2aws/pkg/creds"
	"github.com/pkg/errors"
	saml2aws "github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/samlcache"
)

type awsProvisioner struct {
	stsProvisioner    STSProvisioner
	envVarProvisioner provision.EnvVarProvisioner
}

func AWSProvisioner() sdk.Provisioner {
	return awsProvisioner{
		envVarProvisioner: provision.EnvVarProvisioner{
			Schema: defaultEnvVarMapping,
		},
	}
}

func (p awsProvisioner) Provision(ctx context.Context, in sdk.ProvisionInput, out *sdk.ProvisionOutput) {
	/*
		totp, hasTotp := in.ItemFields[fieldname.OneTimePassword]
		mfaSerial, hasMFASerial := in.ItemFields[fieldname.MFASerial]

		if hasTotp && hasMFASerial {
			p.stsProvisioner.MFASerial = mfaSerial
			p.stsProvisioner.TOTPCode = totp
			p.stsProvisioner.Provision(ctx, in, out)
		} else {
			p.envVarProvisioner.Provision(ctx, in, out)
		}
	*/
	err := p.provisionSAML()
	if err != nil {
		panic(err)
	}
}

func (p awsProvisioner) provisionSAML() error {
	accountName := "accName"
	username := ""
	password := "pwd"
	mfaToken := "token"

	// TODO: after the hackathon, move the saml cache into the plugin cache
	samlCacheFile := "./saml-cache"

	cacheProvider := &samlcache.SAMLCacheProvider{
		Account:  accountName,
		Filename: samlCacheFile,
	}

	/*
		SAML2AWS_MFA=OKTA
		SAML2AWS_IDP_PROVIDER=Okta
		SAML2AWS_URL=https://1password.okta.com/home/amazon_aws/0oacbnkkgfGssywZl357/272
		SAML2AWS_PASSWORD=op://Private/Oktabun/password
		SAML2AWS_USERNAME=op://Private/Oktabun/username
		SAML2AWS_MFA_TOKEN=$(op item get Oktabun --totp)

		op run -- saml2aws login
		 --skip-prompt
		 --disable-keychain
		 --session-duration 43200
		 --profile agilebits-devel
		 --role arn:aws:iam::729119775555:role/dev_Administrator
		 --region us-east-1'
	*/
	idpAccount := cfg.IDPAccount{
		Name:                  accountName,
		AppID:                 "",
		URL:                   "",
		Username:              "",
		Provider:              "",
		MFA:                   "",
		SkipVerify:            false,
		Timeout:               0,
		AmazonWebservicesURN:  "",
		SessionDuration:       0,
		Profile:               "",
		ResourceID:            "",
		Subdomain:             "",
		RoleARN:               "",
		Region:                "",
		HttpAttemptsCount:     "",
		HttpRetryDelay:        "",
		CredentialsFile:       "",
		SAMLCache:             false,
		SAMLCacheFile:         samlCacheFile,
		TargetURL:             "",
		DisableRememberDevice: false,
		DisableSessions:       false,
		Prompter:              "",
	}
	provider, err := saml2aws.NewSAMLClient(&idpAccount)
	if err != nil {
		return errors.Wrap(err, "Error building IdP client.")
	}

	// BEGIN INIT LOGIN DETAILS
	loginDetails := &creds.LoginDetails{URL: idpAccount.URL, Username: idpAccount.Username, MFAToken: mfaToken}

	// if user disabled keychain, dont use Okta sessions & dont remember Okta MFA device
	if strings.ToLower(idpAccount.Provider) == "okta" {
		idpAccount.DisableSessions = true
		idpAccount.DisableRememberDevice = true
	}

	// log.Printf("%s %s", savedUsername, savedPassword)
	loginDetails.Username = username
	loginDetails.Password = password
	// loginDetails.ClientID = loginFlags.CommonFlags.ClientID
	// loginDetails.ClientSecret = loginFlags.CommonFlags.ClientSecret
	// assume --skip-prompt
	loginDetails

	// END INIT LOGIN DETAILS

	err = provider.Validate(loginDetails)
	if err != nil {
		return errors.Wrap(err, "Error validating login details.")
	}

	var samlAssertion string
	if account.SAMLCache {
		if cacheProvider.IsValid() {
			samlAssertion, err = cacheProvider.ReadRaw()
			if err != nil {
				panic("could not read saml cache")
			}
		} else {
			panic("could not get valid saml cache")
		}
	} else {
		log.Printf("Authenticating as %s ...", loginDetails.Username)
	}
	return nil
}

func (p awsProvisioner) Deprovision(ctx context.Context, in sdk.DeprovisionInput, out *sdk.DeprovisionOutput) {
	// Nothing to do here: environment variables get wiped automatically when the process exits.
}

func (p awsProvisioner) Description() string {
	return p.envVarProvisioner.Description()
}
