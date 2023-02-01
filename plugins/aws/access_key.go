package aws

import (
	"context"
	"os"
	"strings"

	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/importer"
	"github.com/1Password/shell-plugins/sdk/schema"
	"github.com/1Password/shell-plugins/sdk/schema/credname"
	"github.com/1Password/shell-plugins/sdk/schema/fieldname"
	"gopkg.in/ini.v1"
)

func AccessKey() schema.CredentialType {
	return schema.CredentialType{
		Name:          credname.Credentials,
		DocsURL:       sdk.URL("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"),
		ManagementURL: sdk.URL("https://console.aws.amazon.com/iam"),
		Fields: []schema.CredentialField{
			{
				Name:                fieldname.Username,
				MarkdownDescription: "The default region to use for this access key.",
			},
			{
				Name:                fieldname.OneTimePassword,
				MarkdownDescription: "The one-time code value for MFA authentication.",
			},
			{
				Name:                fieldname.Password,
				MarkdownDescription: "ARN of the MFA serial number to use to generate temporary STS credentials if the item contains a TOTP setup.",
			},
		},
		DefaultProvisioner: AWSProvisioner(),
		//Importer: importer.TryAll(
		//	importer.TryEnvVarPair(defaultEnvVarMapping),
		//	importer.TryEnvVarPair(map[string]sdk.FieldName{
		//		"AMAZON_ACCESS_KEY_ID":     fieldname.AccessKeyID,
		//		"AMAZON_SECRET_ACCESS_KEY": fieldname.SecretAccessKey,
		//		"AWS_DEFAULT_REGION":       fieldname.DefaultRegion,
		//	}),
		//	importer.TryEnvVarPair(map[string]sdk.FieldName{
		//		"AWS_ACCESS_KEY":     fieldname.AccessKeyID,
		//		"AWS_SECRET_KEY":     fieldname.SecretAccessKey,
		//		"AWS_DEFAULT_REGION": fieldname.DefaultRegion,
		//	}),
		//	importer.TryEnvVarPair(map[string]sdk.FieldName{
		//		"AWS_ACCESS_KEY":     fieldname.AccessKeyID,
		//		"AWS_ACCESS_SECRET":  fieldname.SecretAccessKey,
		//		"AWS_DEFAULT_REGION": fieldname.DefaultRegion,
		//	}),
		//	TryCredentialsFile(),
		//),
	}
}

//var defaultEnvVarMapping = map[string]sdk.FieldName{
//	"AWS_ACCESS_KEY_ID":     fieldname.AccessKeyID,
//	"AWS_SECRET_ACCESS_KEY": fieldname.SecretAccessKey,
//	"AWS_DEFAULT_REGION":    fieldname.DefaultRegion,
//}

// TryCredentialsFile looks for the access key in the ~/.aws/credentials file.
func TryCredentialsFile() sdk.Importer {
	return importer.TryFile("~/.aws/credentials", func(ctx context.Context, contents importer.FileContents, in sdk.ImportInput, out *sdk.ImportAttempt) {
		credentialsFile, err := contents.ToINI()
		if err != nil {
			out.AddError(err)
			return
		}

		// Read config file from the location set in AWS_CONFIG_FILE env var or from  ~/.aws/config
		configPath := os.Getenv("AWS_CONFIG_FILE")
		if configPath != "" {
			if strings.HasPrefix(configPath, "~") {
				configPath = in.FromHomeDir(configPath[1:])
			} else {
				configPath = in.FromRootDir(configPath)
			}
		} else {
			configPath = in.FromHomeDir(".aws", "config") // default config file location
		}
		var configFile *ini.File
		configContent, err := os.ReadFile(configPath)
		if err != nil && !os.IsNotExist(err) {
			out.AddError(err)
		}
		configFile, err = importer.FileContents(configContent).ToINI()
		if err != nil {
			out.AddError(err)
		}

		for _, section := range credentialsFile.Sections() {
			profileName := section.Name()
			fields := make(map[sdk.FieldName]string)
			if section.HasKey("aws_access_key_id") && section.Key("aws_access_key_id").Value() != "" {
				fields[fieldname.AccessKeyID] = section.Key("aws_access_key_id").Value()
			}

			if section.HasKey("aws_secret_access_key") && section.Key("aws_secret_access_key").Value() != "" {
				fields[fieldname.SecretAccessKey] = section.Key("aws_secret_access_key").Value()
			}

			// read profile configuration from config file
			if configFile != nil {
				configSection := getConfigSectionByProfile(configFile, profileName)
				if configSection != nil {
					if configSection.HasKey("region") && configSection.Key("region").Value() != "" {
						fields[fieldname.DefaultRegion] = configSection.Key("region").Value()
					}
				}
			}

			// add only candidates with required credential fields
			if fields[fieldname.AccessKeyID] != "" && fields[fieldname.SecretAccessKey] != "" {
				out.AddCandidate(sdk.ImportCandidate{
					Fields:   fields,
					NameHint: importer.SanitizeNameHint(profileName),
				})
			}
		}
	})
}
