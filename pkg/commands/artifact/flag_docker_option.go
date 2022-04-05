package artifact

import "github.com/urfave/cli/v2"

//Add by chaoyang
type FlagDockerOption struct {
	UserName      string
	Password      string
	RegistryToken string
	NonSSL        bool
}

func NewFlagDockerOption(ctx *cli.Context) FlagDockerOption {
	return FlagDockerOption{
		UserName:      ctx.String("docker-user"),
		Password:      ctx.String("docker-pwd"),
		RegistryToken: ctx.String("docker-regtoken"),
		NonSSL:        ctx.Bool("non-ssl"),
	}
}
