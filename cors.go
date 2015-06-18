package cors

// Note that I import the versions bundled with vulcand. That will make our lives easier, as we'll use exactly the same versions used
// by vulcand. We are escaping dependency management troubles thanks to Godep.
import (
	"bytes"
	"errors"
	"fmt"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/oxy/utils"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"text/template"

	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mailgun/vulcand/plugin"
)

const (
	Type                       = "cors"
	AccessControlAllowOrigin   = "Access-Control-Allow-Origin"
	AccessControlAllowMethods  = "Access-Control-Allow-Methods"
	AccessControlRequestMethod = "Access-Control-Request-Method"
	Origin                     = "Origin"
)

func GetSpec() *plugin.MiddlewareSpec {
	return &plugin.MiddlewareSpec{
		Type:      Type,       // A short name for the middleware
		FromOther: FromOther,  // Tells vulcand how to rcreate middleware from another one (this is for deserialization)
		FromCli:   FromCli,    // Tells vulcand how to create middleware from command line tool
		CliFlags:  CliFlags(), // Vulcand will add this flags to middleware specific command line tool
	}
}

// CorshMiiddleware struct holds configuration parameters and is used to
// serialize/deserialize the configuration from storage engines.
type CorsMiddleware struct {
	AllowedOrigins map[string][]string
}

// Auth middleware handler
type CorsHandler struct {
	cfg  CorsMiddleware
	next http.Handler
}

// This function will be called each time the request hits the location with this middleware activated
func (a *CorsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get(Origin)
	hostIncluded := false
	var methods []string
	if a.cfg.AllowedOrigins[origin] != nil {
		hostIncluded = true
		methods = a.cfg.AllowedOrigins[origin]
	}
	if a.cfg.AllowedOrigins["*"] != nil {
		hostIncluded = true
		methods = a.cfg.AllowedOrigins["*"]
	}
	if !hostIncluded {
		fmt.Println("Cors Error")
		bw := &bufferWriter{header: make(http.Header), buffer: &bytes.Buffer{}}
		newBody := bytes.NewBufferString("")
		// We stop here, right?
		//a.next.ServeHTTP(bw, r)
		if err := ApplyString("{\"error\": \"forbidden\"}", newBody, r); err != nil {
			fmt.Errorf("Can't write body")
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(newBody.Len()))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		utils.CopyHeaders(w.Header(), bw.Header())
		io.Copy(w, newBody)
		return
	}

	methodOK := false

	if r.Method == "OPTIONS" {
		// Preflight
		if method := r.Header.Get(AccessControlRequestMethod); method != "" {
			for _, a := range methods {
				if a == method || a == "*" {
					methodOK = true
				}
			}
		} else {
			// We don't know what they hell they're doing, but
			// the header will tell them
			methodOK = true
		}
		w.Header().Set(AccessControlAllowOrigin, origin)
		w.Header().Set(AccessControlAllowMethods, strings.Join(methods, ","))
		if !methodOK {
			w.WriteHeader(http.StatusForbidden)

		} else {
			w.WriteHeader(http.StatusOK)
		}
		return
	}

	// Pass the request to the next middleware in chain
	a.next.ServeHTTP(w, r)
}

// This function is optional but handy, used to check input parameters when creating new middlewares
func New(allowedOrigins map[string][]string) (*CorsMiddleware, error) {
	_, err := validateOrigins(allowedOrigins)
	if err != nil {
		return nil, err
	}

	return &CorsMiddleware{allowedOrigins}, nil
}

// This function is important, it's called by vulcand to create a new handler from the middleware config and put it into the
// middleware chain. Note that we need to remember 'next' handler to call
func (c *CorsMiddleware) NewHandler(next http.Handler) (http.Handler, error) {
	return &CorsHandler{next: next, cfg: *c}, nil
}

// String() will be called by loggers inside Vulcand and command line tool.
func (c *CorsMiddleware) String() string {
	return fmt.Sprintf("token=%v, key=%v", c.AllowedOrigins, "********")
}

// FromOther Will be called by Vulcand when engine or API will read the middleware from the serialized format.
// It's important that the signature of the function will be exactly the same, otherwise Vulcand will
// fail to register this middleware.
// The first and the only parameter should be the struct itself, no pointers and other variables.
// Function should return middleware interface and error in case if the parameters are wrong.
func FromOther(c CorsMiddleware) (plugin.Middleware, error) {
	return New(c.AllowedOrigins)
}

// FromCli constructs the middleware from the command line
func FromCli(c *cli.Context) (plugin.Middleware, error) {
	var suppliedOriginsAndMethods map[string][]string
	corsFileName := c.String("corsFile")
	if corsFileName != "" {
		yamlFile, err := ioutil.ReadFile(corsFileName)
		if err != nil {
			fmt.Println("File error")
		}
		yaml.Unmarshal(yamlFile, &suppliedOriginsAndMethods)
	}
	return New(suppliedOriginsAndMethods)
}

// CliFlags will be used by Vulcand construct help and CLI command for the vctl command
func CliFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{"corsFile, cf", "", "YAML file of origins and methods", ""},
	}
}

func ApplyString(in string, out io.Writer, request *http.Request) error {
	t, err := template.New("t").Parse(in)
	if err != nil {
		return err
	}

	if err = t.Execute(out, data{request}); err != nil {
		return err
	}

	return nil
}

type bufferWriter struct {
	header http.Header
	code   int
	buffer *bytes.Buffer
}

func (b *bufferWriter) Close() error {
	return nil
}

func (b *bufferWriter) Header() http.Header {
	return b.header
}

func (b *bufferWriter) Write(buf []byte) (int, error) {
	return b.buffer.Write(buf)
}

// WriteHeader sets rw.Code.
func (b *bufferWriter) WriteHeader(code int) {
	b.code = code
}

func validateOrigins(origins map[string][]string) (bool, error) {
	if len(origins) == 0 {
		return false, errors.New("Must supply at least one origin or '*'")
	}
	for origin, _ := range origins {
		if origin == "" {
			return false, errors.New("Must supply at least one origin or '*'")
		}
	}

	return true, nil
}

// data represents template data that is available to use in templates.
type data struct {
	Request *http.Request
}
