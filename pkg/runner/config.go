package runner

import (
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/cyberheb/gojeksf/pkg/subscraping"
	"gopkg.in/yaml.v3"
)

// MultipleKeyPartsLength is the max length for multiple keys
const MultipleKeyPartsLength = 2

// YAMLIndentCharLength number of chars for identation on write YAML to file
const YAMLIndentCharLength = 4

// ConfigFile contains the fields stored in the configuration file
type ConfigFile struct {
	// Resolvers contains the list of resolvers to use while resolving
	Resolvers []string `yaml:"resolvers,omitempty"`
	// Sources contains a list of sources to use for enumeration
	Sources []string `yaml:"sources,omitempty"`
	// AllSources contains the list of all sources for enumeration (slow)
	AllSources []string `yaml:"all-sources,omitempty"`
	// Recrusive contains the list of recursive subdomain enum sources
	Recursive []string `yaml:"recursive,omitempty"`
	// ExcludeSources contains the sources to not include in the enumeration process
	ExcludeSources []string `yaml:"exclude-sources,omitempty"`
	// API keys for different sources
	Censys         []string `yaml:"censys"`
	SecurityTrails []string `yaml:"securitytrails"`
	Shodan         []string `yaml:"shodan"`
	// Version indicates the version of subfinder installed.
	Version string `yaml:"subfinder-version"`
}

// GetConfigDirectory gets the subfinder config directory for a user
func GetConfigDirectory() (string, error) {
	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	var config string

	directory, err := os.UserHomeDir()
	if err != nil {
		return config, err
	}
	config = directory + "/.config/gojeksf"

	// Create All directory for subfinder even if they exist
	err = os.MkdirAll(config, os.ModePerm)
	if err != nil {
		return config, err
	}

	return config, nil
}

// CheckConfigExists checks if the config file exists in the given path
func CheckConfigExists(configPath string) bool {
	if _, err := os.Stat(configPath); err == nil {
		return true
	} else if os.IsNotExist(err) {
		return false
	}
	return false
}

// MarshalWrite writes the marshaled yaml config to disk
func (c *ConfigFile) MarshalWrite(file string) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	// Indent the spaces too
	enc := yaml.NewEncoder(f)
	enc.SetIndent(YAMLIndentCharLength)
	err = enc.Encode(&c)
	f.Close()
	return err
}

// UnmarshalRead reads the unmarshalled config yaml file from disk
func UnmarshalRead(file string) (ConfigFile, error) {
	config := ConfigFile{}

	f, err := os.Open(file)
	if err != nil {
		return config, err
	}
	err = yaml.NewDecoder(f).Decode(&config)
	f.Close()
	return config, err
}

// GetKeys gets the API keys from config file and creates a Keys struct
// We use random selection of api keys from the list of keys supplied.
// Keys that require 2 options are separated by colon (:).
func (c *ConfigFile) GetKeys() subscraping.Keys {
	keys := subscraping.Keys{}

	if len(c.Censys) > 0 {
		censysKeys := c.Censys[rand.Intn(len(c.Censys))]
		parts := strings.Split(censysKeys, ":")
		if len(parts) == MultipleKeyPartsLength {
			keys.CensysToken = parts[0]
			keys.CensysSecret = parts[1]
		}
	}

	if len(c.SecurityTrails) > 0 {
		keys.Securitytrails = c.SecurityTrails[rand.Intn(len(c.SecurityTrails))]
	}
	if len(c.Shodan) > 0 {
		keys.Shodan = c.Shodan[rand.Intn(len(c.Shodan))]
	}

	return keys
}
