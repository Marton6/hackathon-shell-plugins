package aws

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"

	b64 "encoding/base64"

	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/provision"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/pkg/awsconfig"
	"github.com/versent/saml2aws/pkg/creds"
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
	if idpAccount.SAMLCache {
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

	if samlAssertion == "" {
		// samlAssertion was not cached
		samlAssertion, err = provider.Authenticate(loginDetails)
		if err != nil {
			return errors.Wrap(err, "Error authenticating to IdP.")
		}
		if idpAccount.SAMLCache {
			err = cacheProvider.WriteRaw(samlAssertion)
			if err != nil {
				return errors.Wrap(err, "Could not write SAML cache.")
			}
		}
	}

	if samlAssertion == "" {
		log.Println("Response did not contain a valid SAML assertion.")
		log.Println("Please check that your username and password is correct.")
		log.Println("To see the output follow the instructions in https://github.com/versent/saml2aws#debugging-issues-with-idps")
		return errors.New("Didn't get saml assertions")
	}

	role, err := selectAwsRole(samlAssertion, idpAccount)
	if err != nil {
		return errors.Wrap(err, "Failed to assume role. Please check whether you are permitted to assume the given role for the AWS service.")
	}

	awsCreds, err := loginToStsUsingRole(idpAccount, role, samlAssertion)
	if err != nil {
		return errors.Wrap(err, "Error logging into AWS role using SAML assertion.")
	}

	// instead of writing awsCreds to the aws credentials file, provision them through the environment (?) to the command
	return nil
}

func (p awsProvisioner) Deprovision(ctx context.Context, in sdk.DeprovisionInput, out *sdk.DeprovisionOutput) {
	// Nothing to do here: environment variables get wiped automatically when the process exits.
}

func (p awsProvisioner) Description() string {
	return p.envVarProvisioner.Description()
}

func selectAwsRole(samlAssertion string, account *cfg.IDPAccount) (*saml2aws.AWSRole, error) {
	data, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding SAML assertion.")
	}

	roles, err := saml2aws.ExtractAwsRoles(data)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing AWS roles.")
	}

	if len(roles) == 0 {
		log.Println("No roles to assume.")
		log.Println("Please check you are permitted to assume roles for the AWS service.")
		os.Exit(1)
	}

	awsRoles, err := saml2aws.ParseAWSRoles(roles)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing AWS roles.")
	}

	return resolveRole(awsRoles, samlAssertion, account)
}

func resolveRole(awsRoles []*saml2aws.AWSRole, samlAssertion string, account *cfg.IDPAccount) (*saml2aws.AWSRole, error) {
	var role = new(saml2aws.AWSRole)

	if len(awsRoles) == 1 {
		if account.RoleARN != "" {
			return saml2aws.LocateRole(awsRoles, account.RoleARN)
		}
		return awsRoles[0], nil
	} else if len(awsRoles) == 0 {
		return nil, errors.New("No roles available.")
	}

	samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding SAML assertion.")
	}

	aud, err := saml2aws.ExtractDestinationURL(samlAssertionData)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing destination URL.")
	}

	awsAccounts, err := saml2aws.ParseAWSAccounts(aud, samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing AWS role accounts.")
	}
	if len(awsAccounts) == 0 {
		return nil, errors.New("No accounts available.")
	}

	saml2aws.AssignPrincipals(awsRoles, awsAccounts)

	if account.RoleARN != "" {
		return saml2aws.LocateRole(awsRoles, account.RoleARN)
	}

	for {
		role, err = saml2aws.PromptForAWSRoleSelection(awsAccounts)
		if err == nil {
			break
		}
		log.Println("Error selecting role. Try again.")
	}

	return role, nil
}

func loginToStsUsingRole(account *cfg.IDPAccount, role *saml2aws.AWSRole, samlAssertion string) (*awsconfig.AWSCredentials, error) {

	sess, err := session.NewSession(&aws.Config{
		Region: &account.Region,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create session.")
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(samlAssertion),     // Required
		DurationSeconds: aws.Int64(int64(account.SessionDuration)),
	}

	log.Println("Requesting AWS credentials using SAML assertion.")

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return nil, errors.Wrap(err, "Error retrieving STS credentials using SAML.")
	}

	return &awsconfig.AWSCredentials{
		AWSAccessKey:     aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:     aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken:  aws.StringValue(resp.Credentials.SessionToken),
		AWSSecurityToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:     aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:          resp.Credentials.Expiration.Local(),
		Region:           account.Region,
	}, nil
}
