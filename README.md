# CORS Middleware for Vulcan Proxy
This is an attempt at creating a simple [CORS](http://www.w3.org/TR/cors/) middleware for [Vulcan Proxy](http://vulcanproxy.com)

## Caveats
I hate to start with the negative, but:
* I am pretty new to Go, so there's that
* I am pretty new to Vulcan, so there's that too
* I am scratching an itch, so if my itch didn't touch part of the CORS spec, I didn't scratch it. (A good example is `Access-Control-Allow-Credentials`)

## Install
```
go get github.com/skookum/vulcan-cors
```

## Usage
This presumes you have built new `vulcand` and `vctl` binaries per [the instructions](http://vulcanproxy.com/middlewares.html#example-auth-middleware). Basically, you should be able to add `github.com/skookum/vulcan-cors` to your registry and build your `vulcand` and `vctl` binaries.

1. Create a YAML file of your allowed hosts and methods:
```
"*":
  methods:
    - GET
    - PATCH
  headers:
    - Origin
    - Accept
    - Content-Type
    - X-SPECIFIC
http://allmethods.com:
  methods:
    - "*"
  headers:
    - Origin
    - Accept
    - Content-Type
http://allheaders.com:
  methods:
    - GET
  headers:
    - "*"
http://skookum.com:
  methods:
    - "*"
  headers:
    - "*"
  max_age: 86500
```
(Notice that to allow anything use `"*"`. The quotes are necessary. Probably another caveat.)

2. Add the middleware
```
vctl cors upsert -id=cors_middleware-f someFrontend -corsFile=yourYaml.yml --vulcan=http://yourvulcanhost
```
(`-id` can be whatever you want to call the instance of the middleware)

3. Make CORS enabled requests!

### Remove
```
vctl cors rm -id-cors_middeware -f someFrontend --vulcan=http://yourvulcanhost
```

### Notes

The `Access-Control-Max-Age` header defaults to 86400.

## Roadmap
* Support ALL THE CORS
* Clean it up as my Go goes

## Contributing
1. Write tests
2. Write code
3. Run tests until they pass
4. Run `codeclimate analyze` and fix suggestions
5. Issue PR
