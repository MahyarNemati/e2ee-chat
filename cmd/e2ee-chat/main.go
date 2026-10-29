// Command e2ee-chat is both halves of the system: the blind relay and the
// terminal client that talks through it.
//
//	e2ee-chat serve                                  run the relay
//	e2ee-chat init  -user alice                      create keys and publish a bundle
//	e2ee-chat send  -user alice -to bob -m "hello"   encrypt and queue a message
//	e2ee-chat recv  -user alice                      collect and decrypt
//	e2ee-chat chat  -user alice -to bob              interactive session
//	e2ee-chat safety -user alice -peer bob           the number to compare out of band
//	e2ee-chat demo                                   a scripted conversation, start to finish
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

type command struct {
	name string
	help string
	run  func(ctx context.Context, args []string) error
}

func main() {
	commands := []command{
		{"serve", "run the blind relay", runServe},
		{"init", "generate keys and publish a prekey bundle", runInit},
		{"send", "encrypt a message and hand it to the relay", runSend},
		{"recv", "collect and decrypt queued messages", runRecv},
		{"chat", "an interactive session with one peer", runChat},
		{"safety", "print the safety number to compare out of band", runSafety},
		{"users", "list the names the relay has bundles for", runUsers},
		{"demo", "run a whole conversation in one process", runDemo},
		{"version", "print the version", runVersion},
	}

	if len(os.Args) < 2 {
		usage(commands)
		os.Exit(2)
	}
	name := os.Args[1]
	for _, c := range commands {
		if c.name == name {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := c.run(ctx, os.Args[2:]); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				fmt.Fprintf(os.Stderr, "e2ee-chat %s: %v\n", name, err)
				os.Exit(1)
			}
			return
		}
	}
	fmt.Fprintf(os.Stderr, "e2ee-chat: unknown command %q\n\n", name)
	usage(commands)
	os.Exit(2)
}

func usage(commands []command) {
	fmt.Fprintf(os.Stderr, "e2ee-chat %s -- end-to-end encrypted chat over a relay that can decrypt nothing\n\n", version)
	fmt.Fprintln(os.Stderr, "usage: e2ee-chat <command> [flags]")
	fmt.Fprintln(os.Stderr)
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %-8s %s\n", c.name, c.help)
	}
	fmt.Fprintln(os.Stderr, "\nRun 'e2ee-chat <command> -h' for the flags of one command.")
}

func runVersion(context.Context, []string) error {
	fmt.Println(version)
	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: e2ee-chat %s [flags]\n\n", name)
		fs.PrintDefaults()
	}
	return fs
}
