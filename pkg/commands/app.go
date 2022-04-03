package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/commands/plugin"
	"github.com/aquasecurity/trivy/pkg/commands/server"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// VersionInfo holds the trivy DB version Info
type VersionInfo struct {
	Version         string             `json:",omitempty"`
	VulnerabilityDB *metadata.Metadata `json:",omitempty"`
}

var (
	templateFlag = cli.StringFlag{
		Name:    "template",
		Aliases: []string{"t"},
		Value:   "",
		Usage:   "output template",
		EnvVars: []string{"TRIVY_TEMPLATE"},
	}

	formatFlag = cli.StringFlag{
		Name:    "format",
		Aliases: []string{"f"},
		Value:   "table",
		Usage:   "format (table, json, sarif, template, remote)",
		EnvVars: []string{"TRIVY_FORMAT"},
	}

	inputFlag = cli.StringFlag{
		Name:    "input",
		Aliases: []string{"i"},
		Value:   "",
		Usage:   "input file path instead of image name",
		EnvVars: []string{"TRIVY_INPUT"},
	}

	severityFlag = cli.StringFlag{
		Name:    "severity",
		Aliases: []string{"s"},
		Value:   strings.Join(dbTypes.SeverityNames, ","),
		Usage:   "severities of vulnerabilities to be displayed (comma separated)",
		EnvVars: []string{"TRIVY_SEVERITY"},
	}

	outputFlag = cli.StringFlag{
		Name:    "output",
		Aliases: []string{"o"},
		Usage:   "output file name or remote addr",
		EnvVars: []string{"TRIVY_OUTPUT"},
	}

	exitCodeFlag = cli.IntFlag{
		Name:    "exit-code",
		Usage:   "Exit code when vulnerabilities were found",
		Value:   0,
		EnvVars: []string{"TRIVY_EXIT_CODE"},
	}

	skipDBUpdateFlag = cli.BoolFlag{
		Name:    "skip-db-update",
		Aliases: []string{"skip-update"},
		Usage:   "skip updating vulnerability database",
		EnvVars: []string{"TRIVY_SKIP_UPDATE", "TRIVY_SKIP_DB_UPDATE"},
	}

	skipPolicyUpdateFlag = cli.BoolFlag{
		Name:    "skip-policy-update",
		Usage:   "skip updating built-in policies",
		EnvVars: []string{"TRIVY_SKIP_POLICY_UPDATE"},
	}

	downloadDBOnlyFlag = cli.BoolFlag{
		Name:    "download-db-only",
		Usage:   "download/update vulnerability database but don't run a scan",
		EnvVars: []string{"TRIVY_DOWNLOAD_DB_ONLY"},
	}

	resetFlag = cli.BoolFlag{
		Name:    "reset",
		Usage:   "remove all caches and database",
		EnvVars: []string{"TRIVY_RESET"},
	}

	clearCacheFlag = cli.BoolFlag{
		Name:    "clear-cache",
		Aliases: []string{"c"},
		Usage:   "clear image caches without scanning",
		EnvVars: []string{"TRIVY_CLEAR_CACHE"},
	}

	quietFlag = cli.BoolFlag{
		Name:    "quiet",
		Aliases: []string{"q"},
		Usage:   "suppress progress bar and log output",
		EnvVars: []string{"TRIVY_QUIET"},
	}

	noProgressFlag = cli.BoolFlag{
		Name:    "no-progress",
		Usage:   "suppress progress bar",
		EnvVars: []string{"TRIVY_NO_PROGRESS"},
	}

	ignoreUnfixedFlag = cli.BoolFlag{
		Name:    "ignore-unfixed",
		Usage:   "display only fixed vulnerabilities",
		EnvVars: []string{"TRIVY_IGNORE_UNFIXED"},
	}

	debugFlag = cli.BoolFlag{
		Name:    "debug",
		Aliases: []string{"d"},
		Usage:   "debug mode",
		EnvVars: []string{"TRIVY_DEBUG"},
	}

	removedPkgsFlag = cli.BoolFlag{
		Name:    "removed-pkgs",
		Usage:   "detect vulnerabilities of removed packages (only for Alpine)",
		EnvVars: []string{"TRIVY_REMOVED_PKGS"},
	}

	vulnTypeFlag = cli.StringFlag{
		Name:    "vuln-type",
		Value:   strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","),
		Usage:   "comma-separated list of vulnerability types (os,library)",
		EnvVars: []string{"TRIVY_VULN_TYPE"},
	}

	securityChecksFlag = cli.StringFlag{
		Name:    "security-checks",
		Value:   types.SecurityCheckVulnerability,
		Usage:   "comma-separated list of what security issues to detect (vuln,config)",
		EnvVars: []string{"TRIVY_SECURITY_CHECKS"},
	}

	cacheDirFlag = cli.StringFlag{
		Name:    "cache-dir",
		Value:   utils.DefaultCacheDir(),
		Usage:   "cache directory",
		EnvVars: []string{"TRIVY_CACHE_DIR"},
	}

	cacheBackendFlag = cli.StringFlag{
		Name:    "cache-backend",
		Value:   "fs",
		Usage:   "cache backend (e.g. redis://localhost:6379)",
		EnvVars: []string{"TRIVY_CACHE_BACKEND"},
	}

	redisBackendCACert = cli.StringFlag{
		Name:    "redis-ca",
		Usage:   "redis ca file location, if using redis as cache backend",
		EnvVars: []string{"TRIVY_REDIS_BACKEND_CA"},
		Hidden:  true,
	}

	redisBackendCert = cli.StringFlag{
		Name:    "redis-cert",
		Usage:   "redis certificate file location, if using redis as cache backend",
		EnvVars: []string{"TRIVY_REDIS_BACKEND_CERT"},
		Hidden:  true,
	}

	redisBackendKey = cli.StringFlag{
		Name:    "redis-key",
		Usage:   "redis key file location, if using redis as cache backend",
		EnvVars: []string{"TRIVY_REDIS_BACKEND_KEY"},
		Hidden:  true,
	}

	ignoreFileFlag = cli.StringFlag{
		Name:    "ignorefile",
		Value:   result.DefaultIgnoreFile,
		Usage:   "specify .trivyignore file",
		EnvVars: []string{"TRIVY_IGNOREFILE"},
	}

	timeoutFlag = cli.DurationFlag{
		Name:    "timeout",
		Value:   time.Second * 300,
		Usage:   "timeout",
		EnvVars: []string{"TRIVY_TIMEOUT"},
	}

	// TODO: remove this flag after a sufficient deprecation period.
	lightFlag = cli.BoolFlag{
		Name:    "light",
		Usage:   "deprecated",
		EnvVars: []string{"TRIVY_LIGHT"},
	}

	token = cli.StringFlag{
		Name:    "token",
		Usage:   "for authentication in client/server mode",
		EnvVars: []string{"TRIVY_TOKEN"},
	}

	tokenHeader = cli.StringFlag{
		Name:    "token-header",
		Value:   option.DefaultTokenHeader,
		Usage:   "specify a header name for token in client/server mode",
		EnvVars: []string{"TRIVY_TOKEN_HEADER"},
	}

	ignorePolicy = cli.StringFlag{
		Name:    "ignore-policy",
		Usage:   "specify the Rego file to evaluate each vulnerability",
		EnvVars: []string{"TRIVY_IGNORE_POLICY"},
	}

	listAllPackages = cli.BoolFlag{
		Name:    "list-all-pkgs",
		Usage:   "enabling the option will output all packages regardless of vulnerability",
		EnvVars: []string{"TRIVY_LIST_ALL_PKGS"},
	}

	skipFiles = cli.StringSliceFlag{
		Name:    "skip-files",
		Usage:   "specify the file paths to skip traversal",
		EnvVars: []string{"TRIVY_SKIP_FILES"},
	}

	skipDirs = cli.StringSliceFlag{
		Name:    "skip-dirs",
		Usage:   "specify the directories where the traversal is skipped",
		EnvVars: []string{"TRIVY_SKIP_DIRS"},
	}

	offlineScan = cli.BoolFlag{
		Name:    "offline-scan",
		Usage:   "do not issue API requests to identify dependencies",
		EnvVars: []string{"TRIVY_OFFLINE_SCAN"},
	}

	// For misconfigurations
	configPolicy = cli.StringSliceFlag{
		Name:    "config-policy",
		Usage:   "specify paths to the Rego policy files directory, applying config files",
		EnvVars: []string{"TRIVY_CONFIG_POLICY"},
	}

	configPolicyAlias = cli.StringSliceFlag{
		Name:    "policy",
		Aliases: []string{"config-policy"},
		Usage:   "specify paths to the Rego policy files directory, applying config files",
		EnvVars: []string{"TRIVY_POLICY"},
	}

	configData = cli.StringSliceFlag{
		Name:    "config-data",
		Usage:   "specify paths from which data for the Rego policies will be recursively loaded",
		EnvVars: []string{"TRIVY_CONFIG_DATA"},
	}

	configDataAlias = cli.StringSliceFlag{
		Name:    "data",
		Aliases: []string{"config-data"},
		Usage:   "specify paths from which data for the Rego policies will be recursively loaded",
		EnvVars: []string{"TRIVY_DATA"},
	}

	filePatterns = cli.StringSliceFlag{
		Name:    "file-patterns",
		Usage:   "specify file patterns",
		EnvVars: []string{"TRIVY_FILE_PATTERNS"},
	}

	policyNamespaces = cli.StringSliceFlag{
		Name:    "policy-namespaces",
		Aliases: []string{"namespaces"},
		Usage:   "Rego namespaces",
		Value:   cli.NewStringSlice("users"),
		EnvVars: []string{"TRIVY_POLICY_NAMESPACES"},
	}

	includeNonFailures = cli.BoolFlag{
		Name:    "include-non-failures",
		Usage:   "include successes and exceptions",
		Value:   false,
		EnvVars: []string{"TRIVY_INCLUDE_NON_FAILURES"},
	}

	traceFlag = cli.BoolFlag{
		Name:    "trace",
		Usage:   "enable more verbose trace output for custom queries",
		Value:   false,
		EnvVars: []string{"TRIVY_TRACE"},
	}

	insecureFlag = cli.BoolFlag{
		Name:    "insecure",
		Usage:   "allow insecure server connections when using SSL",
		Value:   false,
		EnvVars: []string{"TRIVY_INSECURE"},
	}

	remoteServer = cli.StringFlag{
		Name:    "server",
		Usage:   "server address",
		EnvVars: []string{"TRIVY_SERVER"},
	}

	customHeaders = cli.StringSliceFlag{
		Name:    "custom-headers",
		Usage:   "custom headers in client/server mode",
		EnvVars: []string{"TRIVY_CUSTOM_HEADERS"},
	}

	taskProcessFlag = cli.StringFlag{
		Name:    "task-process",
		Usage:   "taskId|processNo|taskProcessId",
		EnvVars: []string{"TRIVY_TASK_PROCESS"},
	}

	resultRemoteFlag = cli.StringFlag{
		Name:    "resultRemote",
		Usage:   "result http request send address",
		Value:   "http://127.0.0.1:8098",
		EnvVars: []string{"TRIVY_RESULT_REMOTE"},
	}

	// Global flags
	globalFlags = []cli.Flag{
		&quietFlag,
		&debugFlag,
		&cacheDirFlag,
	}
)

// NewApp is the factory method to return Trivy CLI
func NewApp(version string) *cli.App {
	cli.VersionPrinter = func(c *cli.Context) {
		showVersion(c.String("cache-dir"), c.String("format"), c.App.Version, c.App.Writer)
	}

	app := cli.NewApp()
	app.Name = "trivy"
	app.Version = version
	app.ArgsUsage = "target"
	app.Usage = "A simple and comprehensive vulnerability scanner for containers"
	app.EnableBashCompletion = true
	app.Flags = globalFlags

	if runAsPlugin := os.Getenv("TRIVY_RUN_AS_PLUGIN"); runAsPlugin != "" {
		app.Action = func(ctx *cli.Context) error {
			return plugin.RunWithArgs(ctx.Context, runAsPlugin, ctx.Args().Slice())
		}
		app.HideVersion = true
		app.HideHelp = true
		app.HideHelpCommand = true
		app.Flags = append(app.Flags, &cli.BoolFlag{
			Name:    "help",
			Aliases: []string{"h"},
		})
		return app
	}

	app.Commands = []*cli.Command{
		NewImageCommand(),
		NewFilesystemCommand(),
		NewRootfsCommand(),
		NewSbomCommand(),
		NewRepositoryCommand(),
		NewClientCommand(),
		NewServerCommand(),
		NewConfigCommand(),
		NewPluginCommand(),
		NewVersionCommand(),
	}
	app.Commands = append(app.Commands, plugin.LoadCommands()...)

	return app
}

func RunServerCommand(args []string) error {
	cli.VersionPrinter = func(c *cli.Context) {
		showVersion(c.String("cache-dir"), c.String("format"), c.App.Version, c.App.Writer)
	}

	app := cli.NewApp()
	app.Name = "trivy"
	app.ArgsUsage = "target"
	app.Usage = "A simple and comprehensive vulnerability scanner for containers"
	app.EnableBashCompletion = true
	app.Flags = globalFlags
	set := flag.NewFlagSet("scanServer", 0)
	_ = set.Parse(args)

	c := cli.NewContext(app, set, nil)

	serverApp := NewServerCommand()
	err := serverApp.Run(c)

	return err
}

func showVersion(cacheDir, outputFormat, version string, outputWriter io.Writer) {
	var dbMeta *metadata.Metadata

	mc := metadata.NewClient(cacheDir)
	meta, _ := mc.Get() // nolint: errcheck
	if !meta.UpdatedAt.IsZero() && !meta.NextUpdate.IsZero() && meta.Version != 0 {
		dbMeta = &metadata.Metadata{
			Version:      meta.Version,
			NextUpdate:   meta.NextUpdate.UTC(),
			UpdatedAt:    meta.UpdatedAt.UTC(),
			DownloadedAt: meta.DownloadedAt.UTC(),
		}
	}

	switch outputFormat {
	case "json":
		b, _ := json.Marshal(VersionInfo{ // nolint: errcheck
			Version:         version,
			VulnerabilityDB: dbMeta,
		})
		fmt.Fprintln(outputWriter, string(b))
	default:
		output := fmt.Sprintf("Version: %s\n", version)
		if dbMeta != nil {
			output += fmt.Sprintf(`Vulnerability DB:
  Version: %d
  UpdatedAt: %s
  NextUpdate: %s
  DownloadedAt: %s
`, dbMeta.Version, dbMeta.UpdatedAt.UTC(), dbMeta.NextUpdate.UTC(), dbMeta.DownloadedAt.UTC())
		}
		fmt.Fprintf(outputWriter, output)
	}
}

// NewImageCommand is the factory method to add image command
func NewImageCommand() *cli.Command {
	return &cli.Command{
		Name:      "image",
		Aliases:   []string{"i"},
		ArgsUsage: "image_name",
		Usage:     "scan an image",
		Action:    artifact.ImageRun,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&inputFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&skipDBUpdateFlag,
			&downloadDBOnlyFlag,
			&resetFlag,
			&clearCacheFlag,
			&noProgressFlag,
			&ignoreUnfixedFlag,
			&removedPkgsFlag,
			&vulnTypeFlag,
			&securityChecksFlag,
			&ignoreFileFlag,
			&timeoutFlag,
			&lightFlag,
			&ignorePolicy,
			&listAllPackages,
			&cacheBackendFlag,
			&redisBackendCACert,
			&redisBackendCert,
			&redisBackendKey,
			&offlineScan,
			&insecureFlag,
			stringSliceFlag(skipFiles),
			stringSliceFlag(skipDirs),
		},
	}
}

// NewFilesystemCommand is the factory method to add filesystem command
func NewFilesystemCommand() *cli.Command {
	return &cli.Command{
		Name:      "filesystem",
		Aliases:   []string{"fs"},
		ArgsUsage: "path",
		Usage:     "scan local filesystem for language-specific dependencies and config files",
		Action:    artifact.FilesystemRun,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&skipDBUpdateFlag,
			&skipPolicyUpdateFlag,
			&clearCacheFlag,
			&ignoreUnfixedFlag,
			&vulnTypeFlag,
			&securityChecksFlag,
			&ignoreFileFlag,
			&cacheBackendFlag,
			&redisBackendCACert,
			&redisBackendCert,
			&redisBackendKey,
			&timeoutFlag,
			&noProgressFlag,
			&ignorePolicy,
			&listAllPackages,
			&offlineScan,
			stringSliceFlag(skipFiles),
			stringSliceFlag(skipDirs),

			// for misconfiguration
			stringSliceFlag(configPolicy),
			stringSliceFlag(configData),
			stringSliceFlag(policyNamespaces),

			// for client/server
			&remoteServer,
			&token,
			&tokenHeader,
			&customHeaders,
		},
	}
}

// NewRootfsCommand is the factory method to add filesystem command
func NewRootfsCommand() *cli.Command {
	return &cli.Command{
		Name:      "rootfs",
		ArgsUsage: "dir",
		Usage:     "scan rootfs",
		Action:    artifact.RootfsRun,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&skipDBUpdateFlag,
			&skipPolicyUpdateFlag,
			&clearCacheFlag,
			&ignoreUnfixedFlag,
			&vulnTypeFlag,
			&securityChecksFlag,
			&ignoreFileFlag,
			&cacheBackendFlag,
			&redisBackendCACert,
			&redisBackendCert,
			&redisBackendKey,
			&timeoutFlag,
			&noProgressFlag,
			&ignorePolicy,
			&listAllPackages,
			&offlineScan,
			stringSliceFlag(skipFiles),
			stringSliceFlag(skipDirs),
			stringSliceFlag(configPolicy),
			stringSliceFlag(configData),
			stringSliceFlag(policyNamespaces),
		},
	}
}

// NewRepositoryCommand is the factory method to add repository command
func NewRepositoryCommand() *cli.Command {
	return &cli.Command{
		Name:      "repository",
		Aliases:   []string{"repo"},
		ArgsUsage: "repo_url",
		Usage:     "scan remote repository",
		Action:    artifact.RepositoryRun,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&inputFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&skipDBUpdateFlag,
			&skipPolicyUpdateFlag,
			&clearCacheFlag,
			&ignoreUnfixedFlag,
			&removedPkgsFlag,
			&vulnTypeFlag,
			&securityChecksFlag,
			&ignoreFileFlag,
			&cacheBackendFlag,
			&redisBackendCACert,
			&redisBackendCert,
			&redisBackendKey,
			&timeoutFlag,
			&noProgressFlag,
			&quietFlag,
			&ignorePolicy,
			&listAllPackages,
			&offlineScan,
			&insecureFlag,
			stringSliceFlag(skipFiles),
			stringSliceFlag(skipDirs),
		},
	}
}

// NewClientCommand is the factory method to add client command
func NewClientCommand() *cli.Command {
	return &cli.Command{
		Name:      "client",
		Aliases:   []string{"c"},
		ArgsUsage: "image_name",
		Usage:     "client mode",
		Action:    artifact.ImageRun,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&inputFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&clearCacheFlag,
			&ignoreUnfixedFlag,
			&removedPkgsFlag,
			&vulnTypeFlag,
			&securityChecksFlag,
			&ignoreFileFlag,
			&timeoutFlag,
			&noProgressFlag,
			&ignorePolicy,
			stringSliceFlag(skipFiles),
			stringSliceFlag(skipDirs),
			stringSliceFlag(configPolicy),
			&listAllPackages,
			&offlineScan,
			&insecureFlag,
			&taskProcessFlag,
			&resultRemoteFlag,

			&token,
			&tokenHeader,
			&customHeaders,

			// original flags
			&cli.StringFlag{
				Name:    "remote",
				Value:   "http://localhost:4954",
				Usage:   "server address",
				EnvVars: []string{"TRIVY_REMOTE"},
			},
		},
	}
}

// NewServerCommand is the factory method to add server command
func NewServerCommand() *cli.Command {
	return &cli.Command{
		Name:    "server",
		Aliases: []string{"s"},
		Usage:   "server mode",
		Action:  server.Run,
		Flags: []cli.Flag{
			&skipDBUpdateFlag,
			&downloadDBOnlyFlag,
			&resetFlag,
			&cacheBackendFlag,
			&redisBackendCACert,
			&redisBackendCert,
			&redisBackendKey,

			// original flags
			&token,
			&tokenHeader,
			&cli.StringFlag{
				Name:    "listen",
				Value:   "localhost:4954",
				Usage:   "listen address",
				EnvVars: []string{"TRIVY_LISTEN"},
			},
		},
	}
}

// NewConfigCommand adds config command
func NewConfigCommand() *cli.Command {
	return &cli.Command{
		Name:      "config",
		Aliases:   []string{"conf"},
		ArgsUsage: "dir",
		Usage:     "scan config files",
		Action:    artifact.ConfigRun,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&skipPolicyUpdateFlag,
			&resetFlag,
			&clearCacheFlag,
			&ignoreFileFlag,
			&timeoutFlag,
			stringSliceFlag(skipFiles),
			stringSliceFlag(skipDirs),
			stringSliceFlag(configPolicyAlias),
			stringSliceFlag(configDataAlias),
			stringSliceFlag(policyNamespaces),
			stringSliceFlag(filePatterns),
			&includeNonFailures,
			&traceFlag,
		},
	}
}

// NewPluginCommand is the factory method to add plugin command
func NewPluginCommand() *cli.Command {
	return &cli.Command{
		Name:      "plugin",
		Aliases:   []string{"p"},
		ArgsUsage: "plugin_uri",
		Usage:     "manage plugins",
		Subcommands: cli.Commands{
			{
				Name:      "install",
				Aliases:   []string{"i"},
				Usage:     "install a plugin",
				ArgsUsage: "URL | FILE_PATH",
				Action:    plugin.Install,
			},
			{
				Name:      "uninstall",
				Aliases:   []string{"u"},
				Usage:     "uninstall a plugin",
				ArgsUsage: "PLUGIN_NAME",
				Action:    plugin.Uninstall,
			},
			{
				Name:    "list",
				Aliases: []string{"l"},
				Usage:   "list installed plugin",
				Action:  plugin.List,
			},
			{
				Name:      "info",
				Usage:     "information about a plugin",
				ArgsUsage: "PLUGIN_NAME",
				Action:    plugin.Information,
			},
			{
				Name:      "run",
				Aliases:   []string{"r"},
				Usage:     "run a plugin on the fly",
				ArgsUsage: "PLUGIN_NAME [PLUGIN_OPTIONS]",
				Action:    plugin.Run,
			},
			{
				Name:      "update",
				Usage:     "update an existing plugin",
				ArgsUsage: "PLUGIN_NAME",
				Action:    plugin.Update,
			},
		},
	}
}

// NewSbomCommand is the factory method to add sbom command
func NewSbomCommand() *cli.Command {
	return &cli.Command{
		Name:        "sbom",
		ArgsUsage:   "ARTIFACT",
		Usage:       "generate SBOM for an artifact",
		Description: `ARTIFACT can be a container image, file path/directory, git repository or container image archive. See examples.`,
		CustomHelpTemplate: cli.CommandHelpTemplate + `EXAMPLES:
  - image scanning:
      $ trivy sbom alpine:3.15

  - filesystem scanning:
      $ trivy sbom --artifact-type fs /path/to/myapp

  - git repository scanning:
      $ trivy sbom --artifact-type repo github.com/aquasecurity/trivy-ci-test

  - image archive scanning:
      $ trivy sbom --artifact-type archive ./alpine.tar

`,
		Action: artifact.SbomRun,
		Flags: []cli.Flag{
			&outputFlag,
			&clearCacheFlag,
			&ignoreFileFlag,
			&timeoutFlag,
			&severityFlag,
			&offlineScan,
			stringSliceFlag(skipFiles),
			stringSliceFlag(skipDirs),

			// dedicated options
			&cli.StringFlag{
				Name:    "artifact-type",
				Aliases: []string{"type"},
				Value:   "image",
				Usage:   "input artifact type (image, fs, repo, archive)",
				EnvVars: []string{"TRIVY_ARTIFACT_TYPE"},
			},
			&cli.StringFlag{
				Name:    "sbom-format",
				Aliases: []string{"format"},
				Value:   "cyclonedx",
				Usage:   "SBOM format (cyclonedx)",
				EnvVars: []string{"TRIVY_SBOM_FORMAT"},
			},
		},
	}
}

// NewVersionCommand adds version command
func NewVersionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "print the version",
		Action: func(ctx *cli.Context) error {
			showVersion(ctx.String("cache-dir"), ctx.String("format"), ctx.App.Version, ctx.App.Writer)
			return nil
		},
		Flags: []cli.Flag{
			&formatFlag,
		},
	}
}

// StringSliceFlag is defined globally. When the app runs multiple times,
// the previous value will be retained and it causes unexpected results.
// The flag value is copied through this function to prevent the issue.
func stringSliceFlag(f cli.StringSliceFlag) *cli.StringSliceFlag {
	return &f
}
