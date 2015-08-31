package cors

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"

	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mailgun/vulcand/plugin"
)

// Type represents the type of Vulcan middleware.
const Type string = "cors"

// GetSpec is part of the Vulcan middleware interface.
func GetSpec() *plugin.MiddlewareSpec {
	return &plugin.MiddlewareSpec{
		Type:      Type,       // A short name for the middleware
		FromOther: FromOther,  // Tells Vulcan how to create middleware from another one
		FromCli:   FromCli,    // Tell Vulcan how to create middleware from command line tool
		CliFlags:  CliFlags(), // Vulcan will add this flags to middleware specific command line tool
	}
}

// New checks input paramters and initializes the middleware
func New(allowedOrigins map[string]*host) (*Middleware, error) {
	_, err := validateConfig(allowedOrigins)
	if err != nil {
		return nil, err
	}

	return &Middleware{allowedOrigins}, nil
}

// FromOther Will be called by Vulcand when engine or API will read the middleware from the serialized format.
// It's important that the signature of the function will be exactly the same, otherwise Vulcand will fail to register this middleware.
// The first and the only parameter should be the struct itself, no pointers and other variables.
// Function should return middleware interface and error in case if the parameters are wrong.
func FromOther(m Middleware) (plugin.Middleware, error) {
	return New(m.AllowedOrigins)
}

// FromCli constructs the middleware from the command line.
func FromCli(c *cli.Context) (plugin.Middleware, error) {
	var suppliedConfig map[string]*host

	configFile := c.String(corsFile)
	if configFile != "" {
		yamlFile, err := ioutil.ReadFile(configFile)
		if err != nil {
			fmt.Println(errorFileIO)
		}

		yaml.Unmarshal(yamlFile, &suppliedConfig)
	}

	return New(suppliedConfig)
}

// CliFlags will be used by Vulcan construct help and CLI command for `vctl`
func CliFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{"corsFile, cf", "", "YAML configuration file", ""},
	}
}

// Validates the configuration file.
func validateConfig(origins map[string]*host) (bool, error) {
	if len(origins) == 0 {
		return false, errors.New(errorConfigOrigin)
	}

	for origin, cfg := range origins {
		if origin == "" {
			return false, errors.New(errorConfigOrigin)
		}

		if len(cfg.Methods) == 0 {
			return false, errors.New(errorConfigMethod)
		}

		if len(cfg.Headers) == 0 {
			return false, errors.New(errorConfigHeader)
		}

		var canonicalHeaders []string
		for _, h := range cfg.Headers {
			canonicalHeaders = append(canonicalHeaders, http.CanonicalHeaderKey(h))
		}

		cfg.Headers = canonicalHeaders
	}

	return true, nil
}
