package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/MahyarNemati/e2ee-chat/internal/server"
	"github.com/MahyarNemati/e2ee-chat/internal/x3dh"
)

// transport is the client's view of the relay. Every method here moves either
// public key material or opaque ciphertext; there is nothing else to move.
type transport struct {
	baseURL string
	http    *http.Client
}

func (t transport) publish(ctx context.Context, p x3dh.Published) error {
	return t.do(ctx, http.MethodPost, "/v1/bundles", p, nil)
}

func (t transport) bundle(ctx context.Context, name string) (x3dh.Bundle, error) {
	var b x3dh.Bundle
	err := t.do(ctx, http.MethodGet, "/v1/bundles/"+url.PathEscape(name), nil, &b)
	return b, err
}

func (t transport) preKeyCount(ctx context.Context, name string) (int, error) {
	var out struct {
		Remaining int `json:"remaining"`
	}
	err := t.do(ctx, http.MethodGet, "/v1/prekeys/"+url.PathEscape(name)+"/count", nil, &out)
	return out.Remaining, err
}

func (t transport) send(ctx context.Context, from, to string, ciphertext []byte) error {
	body := struct {
		From       string `json:"from"`
		To         string `json:"to"`
		Ciphertext []byte `json:"ciphertext"`
	}{from, to, ciphertext}
	return t.do(ctx, http.MethodPost, "/v1/messages", body, nil)
}

func (t transport) receive(ctx context.Context, name string) ([]server.Envelope, error) {
	var out struct {
		Messages []server.Envelope `json:"messages"`
	}
	err := t.do(ctx, http.MethodGet, "/v1/messages/"+url.PathEscape(name), nil, &out)
	return out.Messages, err
}

func (t transport) users(ctx context.Context) ([]string, error) {
	var out struct {
		Users []string `json:"users"`
	}
	err := t.do(ctx, http.MethodGet, "/v1/users", nil, &out)
	return out.Users, err
}

func (t transport) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("client: encode request: %w", err)
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(t.baseURL, "/")+path, body)
	if err != nil {
		return fmt.Errorf("client: build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := t.http.Do(req)
	if err != nil {
		return fmt.Errorf("client: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("client: %s %s: relay returned %d: %s", method, path, resp.StatusCode, e.Error)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, server.MaxRequestBytes)).Decode(out); err != nil {
		return fmt.Errorf("client: decode response: %w", err)
	}
	return nil
}
