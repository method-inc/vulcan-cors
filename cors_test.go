package cors

import (
	"testing"

	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"net/http/httptest"

	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mailgun/vulcand/plugin"
)

// Helper method to read the test configuration file.
func readConfigFile() (map[string]*host, error) {
	configFile, err := ioutil.ReadFile("test.yml")
	if err != nil {
		return nil, err
	}

	var config map[string]*host
	yaml.Unmarshal(configFile, &config)

	return config, nil
}

func setupTestServer(key string) *httptest.Server {
	data, _ := readConfigFile()
	config := map[string]*host{key: data[key]}
	cors, _ := New(config)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler, _ := cors.NewHandler(next)

	return httptest.NewServer(handler)
}

func setupTestRequest(method string, url string, origin string) *http.Request {
	req, _ := http.NewRequest(method, url, nil)
	req.Header.Add("Origin", origin)

	return req
}

func TestSpecIsOK(t *testing.T) {
	t.Log("Add CORS Middleware spec to Vulcan registry")

	err := plugin.NewRegistry().AddSpec(GetSpec())
	if err != nil {
		t.Errorf("Expected to be able to add spec but got error %+v", err)
	}
}

func TestNew(t *testing.T) {
	t.Log("Creating CORS Middleware with New method")

	config, err := readConfigFile()
	if err != nil {
		t.Errorf("Received error while processing config file: %+v", err)
	}

	cm, err := New(config)
	if err != nil {
		t.Errorf("Expected to create middleware but got error: %+v", err)
	}

	if cm == nil {
		t.Errorf("Expected a CORS Middleware instance but got %+v", cm)
	}

	if cm.String() == "" {
		t.Errorf("Expected middleware string %+v but got empty string", cm)
	}

	handler, err := cm.NewHandler(nil)
	if err != nil {
		t.Errorf("Expected to received a handler but got error: %+v", err)
	}

	if handler == nil {
		t.Errorf("Expected a CORS Handler instance but got %+v", handler)
	}
}

func TestNewInvalid(t *testing.T) {
	t.Log("Creating CORS Middleware with invalid data")

	_, err := New(map[string]*host{})
	if err == nil {
		t.Errorf("Expected to receive an error but got %+v", err)
	}
}

func TestFromOther(t *testing.T) {
	t.Log("Creating CORS Middleware from other CORS Middleware")

	config, err := readConfigFile()
	if err != nil {
		t.Errorf("Received error while processing config file: %+v", err)
	}

	cm, err := New(config)
	if err != nil {
		t.Errorf("Expected to create middleware but got error: %+v", err)
	}

	if cm == nil {
		t.Errorf("Expected a CORS Middleware instance but got %+v", cm)
	}

	other, err := FromOther(*cm)
	if err != nil {
		t.Errorf("Expected to create other middleware but got error: %+v", err)
	}

	if other == nil {
		t.Errorf("Expected other middleware to equal %+v but got nil", cm)
	}
}

func TestFromCli(t *testing.T) {
	t.Log("Create CORS Middleware from command line")

	app := cli.NewApp()
	app.Name = "CORS Middleware Test"
	executed := false
	app.Action = func(ctx *cli.Context) {
		executed = true
		cm, err := FromCli(ctx)
		if err != nil {
			t.Errorf("Expected to create middleware but got error: %+v", err)
		}

		if cm == nil {
			t.Errorf("Expected CORS Middleware instance but got %+v", cm)
		}

		originCount := len((cm.(*Middleware)).AllowedOrigins)
		if originCount != 4 {
			t.Errorf("Expected 4 origins but got %v", originCount)
		}
	}

	app.Flags = CliFlags()
	app.Run([]string{"CORS Middleware Test", "--corsFile=test.yml"})
	if !executed {
		t.Errorf("Expected CLI app to run but it did not.")
	}
}

func TestAllowAllOrigins(t *testing.T) {
	t.Log("Allow all origins when '*' is provided.")

	origin := "http://skookum.com"
	server := setupTestServer("*")
	defer server.Close()

	req := setupTestRequest("GET", server.URL, origin)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusOK {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusOK, code)
	}

	resOrigin := res.Header.Get(allowOriginHeader)
	if resOrigin != origin {
		t.Errorf("Expected Origin header %v but it was %v", origin, resOrigin)
	}
}

func TestAllowSpecificOrigin(t *testing.T) {
	t.Log("Allow specific origins when '*' is not provided")

	origin := "http://skookum.com"
	server := setupTestServer(origin)
	defer server.Close()

	req := setupTestRequest("GET", server.URL, origin)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusOK {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusOK, code)
	}

	resOrigin := res.Header.Get(allowOriginHeader)
	if resOrigin != origin {
		t.Errorf("Expected Origin header %v but it was %v", origin, resOrigin)
	}
}

func TestDenySpecificOrigin(t *testing.T) {
	t.Log("Deny specific origin when not configured for access")

	origin := "http://notallowed.com"
	server := setupTestServer("http://skookum.com")
	defer server.Close()

	req := setupTestRequest("GET", server.URL, origin)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusForbidden {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusForbidden, code)
	}
}

func TestAllowAllMethods(t *testing.T) {
	t.Log("Allow all methods when '*' is provided")

	origin := "http://allmethods.com"
	server := setupTestServer(origin)
	defer server.Close()

	method := "PUT"
	req := setupTestRequest(method, server.URL, origin)
	req.Header.Add("Access-Control-Request-Method", method)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusOK {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusOK, code)
	}

	resOrigin := res.Header.Get(allowOriginHeader)
	if resOrigin != origin {
		t.Errorf("Expected Origin header %v but it was %v", origin, resOrigin)
	}

	resMethod := res.Header.Get(allowMethodsHeader)
	if resMethod != method {
		t.Errorf("Expected method header %v but it was %v", method, resMethod)
	}
}

func TestAllowSpecificMethod(t *testing.T) {
	t.Log("Allow specific method when '*' is not provided.")

	origin := "http://skookum.com"
	server := setupTestServer("*")
	defer server.Close()

	method := "PATCH"
	req := setupTestRequest(method, server.URL, origin)
	req.Header.Add("Access-Control-Request-Method", method)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusOK {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusOK, code)
	}

	resOrigin := res.Header.Get(allowOriginHeader)
	if resOrigin != origin {
		t.Errorf("Expected Origin header %v but it was %v", origin, resOrigin)
	}

	resMethod := res.Header.Get(allowMethodsHeader)
	if resMethod != method {
		t.Errorf("Expected method header %v but it was %v", method, resMethod)
	}
}

func TestAllowOptionsMethod(t *testing.T) {
	t.Log("Always allow OPTIONS method")

	origin := "http://skookum.com"
	server := setupTestServer("*")
	defer server.Close()

	method := "OPTIONS"
	req := setupTestRequest(method, server.URL, origin)
	req.Header.Add("Access-Control-Request-Method", method)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusOK {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusOK, code)
	}

	resOrigin := res.Header.Get(allowOriginHeader)
	if resOrigin != origin {
		t.Errorf("Expected Origin header %v but it was %v", origin, resOrigin)
	}

	resMethod := res.Header.Get(allowMethodsHeader)
	if resMethod != method {
		t.Errorf("Expected method header %v but it was %v", method, resMethod)
	}
}

func TestDenySpecificMethod(t *testing.T) {
	t.Log("Deny specific method when not configured for access")

	origin := "http://skookum.com"
	server := setupTestServer("*")
	defer server.Close()

	method := "POST"
	req := setupTestRequest(method, server.URL, origin)
	req.Header.Add("Access-Control-Request-Method", method)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusForbidden {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusForbidden, code)
	}
}

func TestAllowAllHeaders(t *testing.T) {
	t.Log("Allow all headers when '*' is provided")

	origin := "http://allheaders.com"
	server := setupTestServer(origin)
	defer server.Close()

	header := "X-CUSTOM"
	req := setupTestRequest("GET", server.URL, origin)
	req.Header.Add(header, "custom header data")
	req.Header.Add(requestHeadersHeader, header)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusOK {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusOK, code)
	}

	resOrigin := res.Header.Get(allowOriginHeader)
	if resOrigin != origin {
		t.Errorf("Expected Origin header %v but it was %v", origin, resOrigin)
	}

	resHeader := res.Header.Get(allowHeadersHeader)
	if resHeader != header {
		t.Errorf("Expected allowed headers %v but it was %v", header, resHeader)
	}
}

func TestAllowSecificHeader(t *testing.T) {
	t.Log("Allow specific header when '*' is not provided")

	origin := "http://skookum.com"
	server := setupTestServer("*")
	defer server.Close()

	header := "X-SPECIFIC"
	req := setupTestRequest("GET", server.URL, origin)
	req.Header.Add(header, "custom header data")
	req.Header.Add(requestHeadersHeader, header)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusOK {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusOK, code)
	}

	resOrigin := res.Header.Get(allowOriginHeader)
	if resOrigin != origin {
		t.Errorf("Expected Origin header %v but it was %v", origin, resOrigin)
	}

	resHeader := res.Header.Get(allowHeadersHeader)
	if resHeader != header {
		t.Errorf("Expected allowed headers %v but it was %v", header, resHeader)
	}
}

func TestDenySpecificHeader(t *testing.T) {
	t.Log("Deny specific header when not configured for access")

	origin := "http://skookum.com"
	server := setupTestServer("*")
	defer server.Close()

	header := "X-VERY-CUSTOM"
	req := setupTestRequest("GET", server.URL, origin)
	req.Header.Add(header, "custom header data")
	req.Header.Add(requestHeadersHeader, header)
	res, err := (&http.Client{}).Do(req)

	if err != nil {
		t.Errorf("Error while processing request: %+v", err)
	}

	code := res.StatusCode
	if code != http.StatusForbidden {
		t.Errorf("Expected HTTP status %v but it was %v", http.StatusForbidden, code)
	}
}
