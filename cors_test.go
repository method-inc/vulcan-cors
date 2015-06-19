package cors

import (
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/oxy/testutils"
	. "github.com/mailgun/vulcand/Godeps/_workspace/src/gopkg.in/check.v1"
	"github.com/mailgun/vulcand/plugin"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCL(t *testing.T) { TestingT(t) }

type CorsSuite struct {
}

var _ = Suite(&CorsSuite{})

// One of the most important tests:
// Make sure the JWT spec is compatible and will be accepted by middleware registry
func (s *CorsSuite) TestSpecIsOK(c *C) {
	c.Assert(plugin.NewRegistry().AddSpec(GetSpec()), IsNil)
}

func (s *CorsSuite) TestNew(c *C) {
	cl, err := New(map[string][]string{
		"google.com": []string{"*"},
	})
	c.Assert(cl, NotNil)
	c.Assert(err, IsNil)

	c.Assert(cl.String(), Not(Equals), "")

	out, err := cl.NewHandler(nil)
	c.Assert(out, NotNil)
	c.Assert(err, IsNil)
}

func (s *CorsSuite) TestNewSpecifiMethods(c *C) {
	cl, err := New(map[string][]string{
		"google.com": []string{"GET", "POST"},
	})
	c.Assert(cl, NotNil)
	c.Assert(err, IsNil)

	c.Assert(cl.String(), Not(Equals), "")

	out, err := cl.NewHandler(nil)
	c.Assert(out, NotNil)
	c.Assert(err, IsNil)
	c.Assert(len(cl.AllowedOrigins["google.com"]), Equals, 2)
}

func (s *CorsSuite) TestNewBadParams(c *C) {
	// Empty pass
	_, err := New(map[string][]string{})
	c.Assert(err, NotNil)
}

func (s *CorsSuite) TestFromOther(c *C) {
	cl, err := New(map[string][]string{
		"google.com": []string{"*"},
	})
	c.Assert(cl, NotNil)
	c.Assert(err, IsNil)

	out, err := FromOther(*cl)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, cl)
}

func (s *CorsSuite) TestCorsFromCli(c *C) {
	app := cli.NewApp()
	app.Name = "test"
	executed := false
	app.Action = func(ctx *cli.Context) {
		executed = true
		out, err := FromCli(ctx)
		c.Assert(out, NotNil)
		c.Assert(err, IsNil)

		a := out.(*CorsMiddleware)
		c.Assert(len(a.AllowedOrigins), Equals, 3)
	}
	app.Flags = CliFlags()
	app.Run([]string{"test", "--corsFile=test.yml"})
	c.Assert(executed, Equals, true)
}

func (s *CorsSuite) TestAllowAllOptionsRequestSuccess(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{"*": []string{"*"}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, _, err := testutils.MakeRequest(srv.URL, testutils.Header(Origin, "http://www.balls.com"), testutils.Method("OPTIONS"))
	c.Assert(err, IsNil)
	c.Assert(re.Header.Get(AccessControlAllowOrigin), Equals, "http://www.balls.com")
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *CorsSuite) TestAllowSpecificOptionsRequestSuccess(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{"http://www.balls.com": []string{"*"}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, _, err := testutils.MakeRequest(srv.URL, testutils.Header(Origin, "http://www.balls.com"), testutils.Method("OPTIONS"))
	c.Assert(err, IsNil)
	c.Assert(re.Header.Get(AccessControlAllowOrigin), Equals, "http://www.balls.com")
	c.Assert(re.Header.Get(AccessControlAllowMethods), Equals, "*")
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *CorsSuite) TestAllowAllMethodSuccess(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{"http://www.balls.com": []string{"*"}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, _, err := testutils.MakeRequest(srv.URL, testutils.Header(Origin, "http://www.balls.com"), testutils.Header(AccessControlRequestMethod, "GET"), testutils.Method("OPTIONS"))
	c.Assert(err, IsNil)
	c.Assert(re.Header.Get(AccessControlAllowOrigin), Equals, "http://www.balls.com")
	c.Assert(re.Header.Get(AccessControlAllowMethods), Equals, "*")
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *CorsSuite) TestAllowSpecificMethodSuccess(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{"http://www.balls.com": []string{"GET", "POST"}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, _, err := testutils.MakeRequest(srv.URL, testutils.Header(Origin, "http://www.balls.com"), testutils.Header(AccessControlRequestMethod, "POST"), testutils.Method("OPTIONS"))
	c.Assert(err, IsNil)
	c.Assert(re.Header.Get(AccessControlAllowOrigin), Equals, "http://www.balls.com")
	c.Assert(re.Header.Get(AccessControlAllowMethods), Equals, "GET,POST")
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *CorsSuite) TestAllowSpecificOptionsRequestFailure(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{"http://www.balls.com": []string{"*"}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, _, err := testutils.MakeRequest(srv.URL, testutils.Header(Origin, "http://www.arse.com"), testutils.Method("OPTIONS"))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusForbidden)
}

func (s *CorsSuite) TestAllowSpecificMethodRequestFailure(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{"http://www.balls.com": []string{""}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, _, err := testutils.MakeRequest(srv.URL, testutils.Header(Origin, "http://www.arse.com"), testutils.Method("OPTIONS"))
	c.Assert(err, IsNil)
	c.Assert(re.Header.Get(AccessControlAllowOrigin), Equals, "null")
	c.Assert(re.StatusCode, Equals, http.StatusForbidden)
}

func (s *CorsSuite) TestAllowSpecificGetRequestSuccess(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{"http://www.balls.com": []string{"*"}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "you got it")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, body, err := testutils.MakeRequest(srv.URL, testutils.Header(Origin, "http://www.balls.com"))
	c.Assert(err, IsNil)
	c.Assert(string(body), Equals, "you got it")
	c.Assert(re.Header.Get(AccessControlAllowOrigin), Equals, "http://www.balls.com")
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *CorsSuite) TestAllowAllGetRequestSuccess(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{"*": []string{"*"}}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "you got it")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, body, err := testutils.MakeRequest(srv.URL, testutils.Header("Origin", "http://www.balls.com"))
	c.Assert(err, IsNil)
	c.Assert(string(body), Equals, "you got it")
	c.Assert(re.Header.Get(AccessControlAllowOrigin), Equals, "http://www.balls.com")
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *CorsSuite) TestAllowSpecificGetMultipleRequestSuccess(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{
		"http://www.balls.com": []string{"*"},
		"http://www.arse.com":  []string{"*"},
	}}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "you got it")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, body, err := testutils.MakeRequest(srv.URL, testutils.Header("Origin", "http://www.balls.com"))
	c.Assert(err, IsNil)
	c.Assert(string(body), Equals, "you got it")
	c.Assert(re.Header.Get(AccessControlAllowOrigin), Equals, "http://www.balls.com")
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *CorsSuite) TestAllowMethodFailure(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{
		"http://www.balls.com": []string{"GET", "POST"},
		"http://www.arse.com":  []string{"*"},
	}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "you got it")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, _, err := testutils.MakeRequest(srv.URL, testutils.Method("PUT"), testutils.Header("Origin", "http://www.balls.com"))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusForbidden)

}

func (s *CorsSuite) TestAllowMethodSuccess(c *C) {
	cors := &CorsMiddleware{AllowedOrigins: map[string][]string{
		"http://www.balls.com": []string{"GET", "POST", "PUT"},
		"http://www.arse.com":  []string{"*"},
	}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "you got it")
	})
	handler, err := cors.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	re, body, err := testutils.MakeRequest(srv.URL, testutils.Method("PUT"), testutils.Header("Origin", "http://www.balls.com"))
	c.Assert(err, IsNil)
	c.Assert(string(body), Equals, "you got it")
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}
