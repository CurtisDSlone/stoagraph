// Package openai is the OpenAI-compatible proposer adapter: a model.Proposer
// that calls a /v1/chat/completions endpoint and returns the completion as an
// untrusted proposal. One adapter covers ollama, vllm, OpenRouter, and OpenAI
// by base_url + key. Hand-rolled over stdlib; no third-party dependency.
package openai

// file-kw: openai compatible proposer adapter chat completions untrusted ollama openrouter vllm fail-closed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CurtisDSlone/stoagraph/stoa-kernel/harness/model"
)

const defaultMaxTokens int64 = 1024

// kw: client base url key model maxtokens http
type Client struct {
	BaseURL   string
	APIKey    string
	Model     string
	MaxTokens int64
	HTTP      *http.Client
}

// kw: chat message role content
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// kw: chat request model max_tokens messages no sampling params
type chatRequest struct {
	Model     string        `json:"model"`
	MaxTokens int64         `json:"max_tokens,omitempty"`
	Messages  []chatMessage `json:"messages"`
}

// kw: chat response served model choices finish_reason error
type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// kw: propose chat completions untrusted fail-closed no temperature
func (c Client) Propose(ctx context.Context, req model.Request) (model.Proposal, error) {
	maxTok := c.MaxTokens
	if maxTok <= 0 {
		maxTok = defaultMaxTokens
	}
	msgs := make([]chatMessage, 0, 2)
	if req.System != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: req.System})
	}
	msgs = append(msgs, chatMessage{Role: "user", Content: req.Input})
	// no temperature/top_p/top_k: steer by prompt, gate is the deterministic layer.
	body, err := json.Marshal(chatRequest{Model: c.Model, MaxTokens: maxTok, Messages: msgs})
	if err != nil {
		return model.Proposal{}, fmt.Errorf("openai: marshal: %w", err)
	}

	url := strings.TrimRight(c.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return model.Proposal{}, fmt.Errorf("openai: request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(httpReq)
	if err != nil {
		return model.Proposal{}, fmt.Errorf("openai: %w", err) // fail closed (inv 8)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return model.Proposal{}, fmt.Errorf("openai: read: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model.Proposal{}, fmt.Errorf("openai: status %d", resp.StatusCode) // fail closed
	}

	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return model.Proposal{}, fmt.Errorf("openai: decode: %w", err) // fail closed
	}
	if cr.Error != nil {
		return model.Proposal{}, fmt.Errorf("openai: api error: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return model.Proposal{}, fmt.Errorf("openai: empty choices") // fail closed
	}
	if cr.Choices[0].FinishReason == "content_filter" {
		return model.Proposal{}, fmt.Errorf("openai: content filtered (declined)") // fail closed
	}

	served := cr.Model
	if served == "" {
		served = c.Model
	}
	// provenance for the OpenAI-compatible dialect; Value is stamped Untrusted by Eval.
	return model.Proposal{Value: cr.Choices[0].Message.Content, Model: "openai:" + served}, nil
}
