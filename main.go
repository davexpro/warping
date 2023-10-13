package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

var (
	flags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "disable-update",
			Value: false,
			Usage: "disable self update",
		},
	}
	commands = []*cli.Command{}
)

func main() {
	w := NewWarping()
	w.Run()
	return
	// init cli
	app := &cli.App{
		Name:     "warping",
		Usage:    "warping <https://github.com/DavexPro/warping>",
		Version:  "v0.1.0",
		Writer:   os.Stdout,
		Flags:    flags,
		Commands: commands,
	}

	// run the cli
	err := app.Run(os.Args)
	if err != nil {
		log.Println(err.Error())
	}
}
