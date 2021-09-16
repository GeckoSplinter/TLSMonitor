package main

import (
	"tlsmonitor/cmd"

	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	cmd.Execute()
}
