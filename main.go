package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tydic.io/dcloud-dhcp-controller/pkg/app"

	log "github.com/sirupsen/logrus"
)

var progname string = "dcloud-dhcp-controller"

func init() {
	// Log as JSON instead of the default ASCII formatter.
	formatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(formatter)
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func CheckEnvs() error {
	envMaps := map[string]bool{
		"POD_NAME":      true,
		"POD_NAMESPACE": true,
	}
	for envKey, _ := range envMaps {
		_, ok := os.LookupEnv(envKey)
		if !ok {
			return fmt.Errorf("the environment variable [%s] that must be defined", envKey)
		}
	}
	return nil
}

func main() {
	log.Infof("(main) starting %s", progname)

	level, err := log.ParseLevel(os.Getenv("LOGLEVEL"))
	if err != nil {
		log.Warnf("(main) cannot determine loglevel, leaving it on Info")
	} else {
		log.Infof("(main) setting loglevel to %s", level)
		log.SetLevel(level)
	}
	if err := CheckEnvs(); err != nil {
		log.Panicf("(main) %s", err.Error())
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	mainApp := app.Register()

	go func() {
		<-sig
		cancel()
		mainApp.RemoveLeaderPodLabel()
		os.Exit(1)
	}()

	mainApp.Init()
	mainApp.Run(ctx)
	cancel()
}
