package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Version will be set by the make build command.
	Version string
	// StartupConfig will be set by the SetStartupConfig function.
	StartupConfig *startupConfig
)

type startupConfig struct {
	DataDir        string `mapstructure:"data_dir"`
	Backlink       string
	HttpHost       string `mapstructure:"http_host"`
	HttpAddr       string `mapstructure:"http_addr"`
	HttpInsecure   bool   `mapstructure:"http_insecure"`
	LetsEncrypt    bool
	Debug          bool
	Theme          string
	DisableDns     bool   `mapstructure:"disable_dns"`
	AllowedIps     string `mapstructure:"allowed_ips"`
	EndpointHost   string `mapstructure:"endpoint_host"`
	ListenPort     string
	Ipv4Cidr       string `mapstructure:"ipv4_cidr"`
	Ipv4Gw         string `mapstructure:"ipv4_gw"`
	Ipv4Pref       string `mapstructure:"ipv4_pref"`
	Ipv4NatEnabled bool   `mapstructure:"ipv4_nat_enabled"`
	Ipv6Cidr       string `mapstructure:"ipv6_cidr"`
	Ipv6Gw         string `mapstructure:"ipv6_gw"`
	Ipv6Pref       string `mapstructure:"ipv6_pref"`
	Ipv6NatEnabled bool   `mapstructure:"ipv6_nat_enabled"`
}

// Execute parse command line arguments and loads the startup config.
// The following sources are considered:
// * Command line arguments
// * Environment variables
// * Config file
// * Defaults set in the code
func SetStartupConfig() {
	rootCmd := &cobra.Command{
		Use: "subspace",
		// This will make cobra add "--version" option
		Version: Version,
		Short:   "Subspace is a frontend for Wireguard configuration & user management",
		// we must have an empty run function (or child commands), otherwise help won't print usage string
		// see https://github.com/spf13/cobra/blob/6d00909120c77b54b0c9974a4e20ffc540901b98/command.go#L527
		Run: func(cmd *cobra.Command, args []string) {},
	}
	var err error
	StartupConfig, err = loadStartupConfig(rootCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

	// Perform command validation

	// Since Cobra is not driving the main function, we need to take care of exiting
	// after a call to help or version
	help, _ := rootCmd.Flags().GetBool("help")
	version, _ := rootCmd.Flags().GetBool("version")
	if help || version {
		os.Exit(0)
	}

	if StartupConfig.HttpHost == "" {
		fmt.Fprintf(os.Stderr, "--http-host is required (either through the command line or a config file)\n\n")
		fmt.Println(rootCmd.UsageString())
		os.Exit(1)
	}
}

func loadStartupConfig(rootCmd *cobra.Command) (*startupConfig, error) {
	rootCmd.Flags().String("config", "", "config file (optional)")
	rootCmd.Flags().String("datadir", "/data", "data dir")
	rootCmd.Flags().String("backlink", "/", "backlink (optional)")
	rootCmd.Flags().String("http-host", "", "HTTP host")
	rootCmd.Flags().String("http-addr", ":80", "HTTP listen address")
	rootCmd.Flags().Bool("http-insecure", false, "enable sessions cookies for http (no https) not recommended")
	rootCmd.Flags().Bool("letsencrypt", true, "enable TLS using Let's Encrypt on port 443")
	rootCmd.Flags().Bool("debug", false, "debug mode")
	rootCmd.Flags().String("theme", "green", "Semantic-ui theme to use")

	if err := rootCmd.Execute(); err != nil {
		return nil, err
	}

	startupConfig, err := unifyConfig(rootCmd)
	return startupConfig, err
}

func unifyConfig(rootCmd *cobra.Command) (*startupConfig, error) {
	viper.BindPFlag("data_dir", rootCmd.Flags().Lookup("datadir"))
	viper.BindPFlag("backlink", rootCmd.Flags().Lookup("backlink"))
	viper.BindPFlag("http_host", rootCmd.Flags().Lookup("http-host"))
	viper.BindPFlag("http_addr", rootCmd.Flags().Lookup("http-addr"))
	viper.BindPFlag("http_insecure", rootCmd.Flags().Lookup("http-insecure"))
	viper.BindPFlag("letsencrypt", rootCmd.Flags().Lookup("letsencrypt"))
	viper.BindPFlag("debug", rootCmd.Flags().Lookup("debug"))
	viper.BindPFlag("theme", rootCmd.Flags().Lookup("theme"))

	// Look for the config file in the current directory if the path isn't absolute
	viper.AddConfigPath(".")
	cfgFile := rootCmd.Flags().Lookup("config").Value.String()
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %s", err)
		} else {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}
	}

	viper.SetEnvPrefix("subspace")
	viper.AutomaticEnv()

	// Setting defaults
	viper.SetDefault("disable_dns", false)
	viper.SetDefault("allowed_ips", "0.0.0.0/0, ::/0")
	viper.SetDefault("listenport", "51820")
	viper.SetDefault("ipv4_cidr", "24")
	viper.SetDefault("ipv4_gw", "10.99.97.1")
	viper.SetDefault("ipv4_pref", "10.99.97.")
	viper.SetDefault("ipv4_nat_enabled", true)
	viper.SetDefault("ipv6_cidr", "64")
	viper.SetDefault("ipv6_gw", "fd00::10:97:1")
	viper.SetDefault("ipv6_pref", "fd00::10:97:")
	viper.SetDefault("ipv6_nat_enabled", true)

	// if endpoint_host was not explicitly set, use http_host
	if viper.GetString("endpoint_host") == "" {
		httpHost := viper.GetString("http_host")
		viper.Set("endpoint_host", httpHost)
	}

	var startupConfig startupConfig
	err := viper.Unmarshal(&startupConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to decode configuration into startupConfig struct, %v", err)
	}
	return &startupConfig, nil
}
