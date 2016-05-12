package cors

const (
	// Response Headers
	allowOriginHeader  string = "Access-Control-Allow-Origin"
	allowMethodsHeader string = "Access-Control-Allow-Methods"
	allowHeadersHeader string = "Access-Control-Allow-Headers"
	maxAgeHeader       string = "Access-Control-Max-Age"

	// Request Headers
	requestMethodHeader  string = "Access-Control-Request-Method"
	requestHeadersHeader string = "Access-Control-Request-Headers"

	// Common Headers
	varyHeader   string = "Vary"
	originHeader string = "Origin"

	// Request Methods
	optionsMethod string = "OPTIONS"

	// Error Messages
	errorRoot         string = "request blocked by CORS:"
	errorBadOrigin    string = "bad host"
	errorBadMethod    string = "bad method"
	errorBadHeader    string = "bad header"
	errorConfigOrigin string = "must supply at least one origin or '*'"
	errorConfigMethod string = "must supply at least one method or '*'"
	errorConfigHeader string = "must supply at least one header or '*'"
	errorFileIO       string = "file error"

	// Common
	allToken string = "*"
	corsFile string = "corsFile"
)
