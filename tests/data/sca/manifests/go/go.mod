module example.com/demo

go 1.21

require github.com/gin-gonic/gin v1.6.3

require (
	golang.org/x/text v0.3.5
	gopkg.in/yaml.v2 v2.2.2 // indirect
)

replace golang.org/x/net => golang.org/x/net v0.0.1

exclude (
	github.com/old/thing v1.0.0
)
