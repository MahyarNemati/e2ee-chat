package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MahyarNemati/e2ee-chat/internal/client"
	"github.com/MahyarNemati/e2ee-chat/internal/keystore"
	"github.com/MahyarNemati/e2ee-chat/internal/safetynum"
	"golang.org/x/term"
)

// passphraseEnv lets scripts and the test suite supply a passphrase without a
// terminal. Anything on a command line ends up in the shell history and in
// /proc, so there is deliberately no -passphrase flag.
const passphraseEnv = "E2EE_CHAT_PASSPHRASE"

type commonFlags struct {
	user   string
	server string
	store  string
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.user, "user", "", "account name (required)")
	fs.StringVar(&c.server, "server", envOr("E2EE_CHAT_SERVER", "http://localhost:8080"), "relay base URL")
	fs.StringVar(&c.store, "store", "", "keystore path (default ~/.e2ee-chat/<user>.keys)")
}

func (c *commonFlags) validate() error {
	if c.user == "" {
		return errors.New("-user is required")
	}
	if c.store == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("locate home directory: %w", err)
		}
		c.store = filepath.Join(home, ".e2ee-chat", c.user+".keys")
	}
	return nil
}

func (c *commonFlags) config() client.Config {
	return client.Config{ServerURL: c.server}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// readPassphrase takes the passphrase from the environment, or prompts without
// echo when there is a terminal.
func readPassphrase(prompt string) ([]byte, error) {
	if v, ok := os.LookupEnv(passphraseEnv); ok {
		if v == "" {
			return nil, fmt.Errorf("%s is set but empty", passphraseEnv)
		}
		return []byte(v), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("no terminal to prompt on; set %s", passphraseEnv)
	}
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}
	return pass, nil
}

func loadClient(c *commonFlags) (*client.Client, []byte, error) {
	pass, err := readPassphrase("passphrase: ")
	if err != nil {
		return nil, nil, err
	}
	cl, err := client.Load(c.store, pass, c.config())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("no keystore at %s -- run 'e2ee-chat init -user %s' first", c.store, c.user)
		}
		return nil, nil, err
	}
	if cl.Name() != c.user {
		return nil, nil, fmt.Errorf("keystore %s belongs to %q, not %q", c.store, cl.Name(), c.user)
	}
	return cl, pass, nil
}

func runInit(ctx context.Context, args []string) error {
	var cf commonFlags
	fs := newFlagSet("init")
	cf.register(fs)
	force := fs.Bool("force", false, "overwrite an existing keystore (destroys every session in it)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := cf.validate(); err != nil {
		return err
	}
	if _, err := os.Stat(cf.store); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass -force to replace it", cf.store)
	}

	pass, err := readPassphrase("new passphrase: ")
	if err != nil {
		return err
	}
	if len(pass) < 8 {
		return errors.New("passphrase must be at least 8 characters")
	}

	cl, err := client.New(cf.user, cf.config())
	if err != nil {
		return err
	}
	if err := cl.Publish(ctx); err != nil {
		return fmt.Errorf("publish prekey bundle: %w", err)
	}
	if err := cl.Save(cf.store, pass, keystore.DefaultParams()); err != nil {
		return err
	}

	fmt.Printf("account %q created\n", cf.user)
	fmt.Printf("  keystore     %s (Argon2id, %d MiB)\n", cf.store, keystore.DefaultParams().MemoryKiB/1024)
	fmt.Printf("  identity key %s\n", mustText(cl))
	fmt.Printf("  published to %s with %d one-time prekeys\n", cf.server, client.DefaultPreKeyPool)
	return nil
}

func mustText(cl *client.Client) string {
	k := cl.IdentityKey()
	b, err := k.MarshalText()
	if err != nil {
		return "<unencodable>"
	}
	return string(b)
}

func runSend(ctx context.Context, args []string) error {
	var cf commonFlags
	fs := newFlagSet("send")
	cf.register(fs)
	to := fs.String("to", "", "recipient account name (required)")
	message := fs.String("m", "", "message text; omit to read one line from stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := cf.validate(); err != nil {
		return err
	}
	if *to == "" {
		return errors.New("-to is required")
	}

	text := *message
	if text == "" {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read message from stdin: %w", err)
		}
		text = strings.TrimRight(line, "\r\n")
	}

	cl, pass, err := loadClient(&cf)
	if err != nil {
		return err
	}
	newSession := !hasPeer(cl, *to)
	if err := cl.Send(ctx, *to, []byte(text)); err != nil {
		return err
	}
	if err := cl.Save(cf.store, pass, keystore.DefaultParams()); err != nil {
		return err
	}

	if newSession {
		number, err := cl.SafetyNumber(*to)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "new session with %q. Compare this safety number with them over a channel\nthe relay does not control -- it is the only thing that detects a substituted key:\n\n%s\n\n",
			*to, indent(safetynum.Format(number)))
	}
	fmt.Printf("sent %d bytes to %s\n", len(text), *to)
	return nil
}

func hasPeer(cl *client.Client, peer string) bool {
	for _, p := range cl.Peers() {
		if p == peer {
			return true
		}
	}
	return false
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}

func runRecv(ctx context.Context, args []string) error {
	var cf commonFlags
	fs := newFlagSet("recv")
	cf.register(fs)
	watch := fs.Duration("watch", 0, "keep polling at this interval instead of returning (for example 2s)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := cf.validate(); err != nil {
		return err
	}

	cl, pass, err := loadClient(&cf)
	if err != nil {
		return err
	}
	for {
		if err := drain(ctx, cl, cf.store, pass, os.Stdout); err != nil {
			return err
		}
		if *watch <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*watch):
		}
	}
}

func drain(ctx context.Context, cl *client.Client, store string, pass []byte, out *os.File) error {
	msgs, err := cl.Receive(ctx)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Err != nil {
			// A message that does not decrypt is reported, never dropped: it is
			// either corruption, a replay, or someone trying something.
			fmt.Fprintf(os.Stderr, "[%s] message from %s REJECTED: %v\n", m.At.Format(time.TimeOnly), m.From, m.Err)
			continue
		}
		if m.NewSession {
			if number, err := cl.SafetyNumber(m.From); err == nil {
				fmt.Fprintf(os.Stderr, "[new session with %s -- safety number]\n%s\n", m.From, indent(safetynum.Format(number)))
			}
		}
		fmt.Fprintf(out, "[%s] %s: %s\n", m.At.Format(time.TimeOnly), m.From, m.Text)
	}
	if len(msgs) > 0 {
		return cl.Save(store, pass, keystore.DefaultParams())
	}
	return nil
}

func runChat(ctx context.Context, args []string) error {
	var cf commonFlags
	fs := newFlagSet("chat")
	cf.register(fs)
	to := fs.String("to", "", "peer account name (required)")
	poll := fs.Duration("poll", time.Second, "how often to check the relay for new messages")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := cf.validate(); err != nil {
		return err
	}
	if *to == "" {
		return errors.New("-to is required")
	}

	cl, pass, err := loadClient(&cf)
	if err != nil {
		return err
	}

	// One client, two goroutines: the poller and the reader. The client holds
	// mutable ratchet state and is not safe for concurrent use, so every call
	// goes through this mutex.
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		ticker := time.NewTicker(*poll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				err := drain(ctx, cl, cf.store, pass, os.Stdout)
				mu.Unlock()
				if err != nil && ctx.Err() == nil {
					fmt.Fprintf(os.Stderr, "poll: %v\n", err)
				}
			}
		}
	}()

	fmt.Fprintf(os.Stderr, "chatting with %s via %s. Type a line to send it; Ctrl-D to leave.\n", *to, cf.server)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		text := scanner.Text()
		if text == "" {
			continue
		}
		mu.Lock()
		err := cl.Send(ctx, *to, []byte(text))
		if err == nil {
			err = cl.Save(cf.store, pass, keystore.DefaultParams())
		}
		mu.Unlock()
		if err != nil {
			fmt.Fprintf(os.Stderr, "send: %v\n", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	return nil
}

func runSafety(_ context.Context, args []string) error {
	var cf commonFlags
	fs := newFlagSet("safety")
	cf.register(fs)
	peer := fs.String("peer", "", "peer account name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := cf.validate(); err != nil {
		return err
	}
	if *peer == "" {
		return errors.New("-peer is required")
	}

	cl, _, err := loadClient(&cf)
	if err != nil {
		return err
	}
	number, err := cl.SafetyNumber(*peer)
	if err != nil {
		return err
	}
	fmt.Printf("safety number for %s <-> %s\n\n%s\n\n", cf.user, *peer, indent(safetynum.Format(number)))
	fmt.Println("Read these digits to each other over a channel the relay does not control.")
	fmt.Println("If they match, no prekey bundle was substituted. If they do not, someone is")
	fmt.Println("between you, and the protocol itself cannot tell you that.")
	return nil
}

func runUsers(ctx context.Context, args []string) error {
	var cf commonFlags
	fs := newFlagSet("users")
	cf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := cf.validate(); err != nil {
		return err
	}
	cl, _, err := loadClient(&cf)
	if err != nil {
		return err
	}
	users, err := cl.Users(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		fmt.Println(u)
	}
	return nil
}
