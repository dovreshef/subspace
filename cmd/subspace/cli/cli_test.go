package cli

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func create_root_cmd(args ...string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "subspace",
		Run: func(_ *cobra.Command, args []string) {},
	}
	rootCmd.SetArgs(args)
	return rootCmd
}

func create_config_file(config string) (string, error) {
	file, err := ioutil.TempFile("", "subspace.*.yaml")
	if err != nil {
		return "", err
	}
	ioutil.WriteFile(file.Name(), []byte(config), 0644)
	return file.Name(), nil
}

func TestDefaults(t *testing.T) {
	rootCmd := create_root_cmd()
	startupConfig, err := loadStartupConfig(rootCmd)
	assert.Equal(t, err, nil, "loadStartupConfig should succeed")
	assert.Equal(t, startupConfig.DataDir, "/data")
	assert.Equal(t, startupConfig.Backlink, "/")
	assert.Equal(t, startupConfig.HttpHost, "")
	assert.Equal(t, startupConfig.HttpAddr, ":80")
	assert.Equal(t, startupConfig.HttpInsecure, false)
	assert.Equal(t, startupConfig.LetsEncrypt, true)
	assert.Equal(t, startupConfig.Debug, false)
	assert.Equal(t, startupConfig.Theme, "green")
	assert.Equal(t, startupConfig.DisableDns, false)
	assert.Equal(t, startupConfig.AllowedIps, "0.0.0.0/0, ::/0")
	assert.Equal(t, startupConfig.EndpointHost, "")
	assert.Equal(t, startupConfig.ListenPort, "51820")
	assert.Equal(t, startupConfig.Ipv4Cidr, "24")
	assert.Equal(t, startupConfig.Ipv4Gw, "10.99.97.1")
	assert.Equal(t, startupConfig.Ipv4Pref, "10.99.97.")
	assert.Equal(t, startupConfig.Ipv4NatEnabled, true)
	assert.Equal(t, startupConfig.Ipv6Cidr, "64")
	assert.Equal(t, startupConfig.Ipv6Gw, "fd00::10:97:1")
	assert.Equal(t, startupConfig.Ipv6Pref, "fd00::10:97:")
	assert.Equal(t, startupConfig.Ipv6NatEnabled, true)
}

func TestConfigFile(t *testing.T) {
	config := `
listenport: 56876
disable_dns: true
ipv4_cidr: 30
`
	fileName, err := create_config_file(config)
	rootCmd := create_root_cmd("--config", fileName)
	assert.Equal(t, err, nil, "create_config_file should succeed")
	defer os.Remove(fileName)
	startupConfig, err := loadStartupConfig(rootCmd)
	assert.Equal(t, err, nil, "loadStartupConfig should succeed")
	assert.Equal(t, startupConfig.ListenPort, "56876")
	assert.Equal(t, startupConfig.DisableDns, true)
	assert.Equal(t, startupConfig.Ipv4Cidr, "30")
}

func TestConfigMix(t *testing.T) {
	os.Setenv("SUBSPACE_IPV4_CIDR", "8")
	config := `
listenport: 56876
letsencrypt: false
ipv4_cidr: 30
`
	fileName, err := create_config_file(config)
	rootCmd := create_root_cmd("--config", fileName, "--letsencrypt", "true")
	assert.Equal(t, err, nil, "create_config_file should succeed")
	defer os.Remove(fileName)
	startupConfig, err := loadStartupConfig(rootCmd)
	assert.Equal(t, err, nil, "loadStartupConfig should succeed")
	assert.Equal(t, startupConfig.ListenPort, "56876")
	// command line has priority over config file
	assert.Equal(t, startupConfig.LetsEncrypt, true)
	// environment variable has priority over config file
	assert.Equal(t, startupConfig.Ipv4Cidr, "8")
	os.Unsetenv("SUBSPACE_IPV4_CIDR")
}
