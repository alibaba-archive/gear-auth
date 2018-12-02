module github.com/teambition/gear-auth

require (
	github.com/SermoDigital/jose v0.0.0-20180104203859-803625baeddc
	github.com/bitly/go-simplejson v0.5.0 // indirect
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dimfeld/httptreemux v5.0.1+incompatible // indirect
	github.com/go-http-utils/cookie v1.3.1 // indirect
	github.com/go-http-utils/negotiator v1.0.0 // indirect
	github.com/julienschmidt/httprouter v1.2.0 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/mozillazg/request v0.8.0
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.2.2
	github.com/teambition/gear v1.12.2
	github.com/teambition/trie-mux v1.4.2 // indirect
	golang.org/x/crypto v0.0.0-20181127143415-eb0de9b17e85
	golang.org/x/net v0.0.0-20181201002055-351d144fa1fc // indirect
	golang.org/x/text v0.3.0 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/mgo.v2 v2.0.0-20180705113604-9856a29383ce // indirect
	gopkg.in/yaml.v2 v2.2.2 // indirect
)

exclude github.com/SermoDigital/jose v0.9.1 // https://github.com/SermoDigital/jose/issues/43

replace (
	golang.org/x/crypto => github.com/golang/crypto v0.0.0-20181030102418-4d3f4d9ffa16
	golang.org/x/net => github.com/golang/net v0.0.0-20181102091132-c10e9556a7bc
	golang.org/x/text => github.com/golang/text v0.3.1-0.20181010134911-4d1c5fb19474
	golang.org/x/tools => github.com/golang/tools v0.0.0-20181016205153-5ef16f43e633
)
