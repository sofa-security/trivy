package types

import (
	"github.com/caarlos0/env/v6"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
)

// DockerConfig holds the config of Docker
type DockerConfig struct {
	UserName      string `env:"TRIVY_USERNAME"`
	Password      string `env:"TRIVY_PASSWORD"`
	RegistryToken string `env:"TRIVY_REGISTRY_TOKEN"`
	NonSSL        bool   `env:"TRIVY_NON_SSL" envDefault:"false"`
}

// GetDockerOption returns the Docker scanning options using DockerConfig
func GetDockerOption(insecureTlsSkip bool, dockerOpt ...string) (types.DockerOption, error) {
	cfg := DockerConfig{}
	if err := env.Parse(&cfg); err != nil {
		return types.DockerOption{}, xerrors.Errorf("unable to parse environment variables: %w", err)
	}
	if dockerOpt != nil {
		n := len(dockerOpt)
		switch n {
		case 2: //NonSSL true, if len == 2
			if dockerOpt[0] != "" && dockerOpt[1] != "" {
				cfg.UserName = dockerOpt[0]
				cfg.Password = dockerOpt[1]
				cfg.NonSSL = true
			}
		case 3:
			if dockerOpt[0] != "" && dockerOpt[1] != "" {
				cfg.UserName = dockerOpt[0]
				cfg.Password = dockerOpt[1]
				cfg.NonSSL = true
			}
			if dockerOpt[2] != "" {
				cfg.RegistryToken = dockerOpt[2]
			}
		default:
			//do noting
		}
	}

	return types.DockerOption{
		UserName:              cfg.UserName,
		Password:              cfg.Password,
		RegistryToken:         cfg.RegistryToken,
		InsecureSkipTLSVerify: insecureTlsSkip,
		NonSSL:                cfg.NonSSL,
	}, nil
}
