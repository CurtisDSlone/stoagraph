package agent

// file-kw: adapter openai-compatible tool-use proposer translate mcp-tools-to-provider-schema base-url

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// openaiModel drives tool-use over the OpenAI-compatible /chat/completions API — covers
// OpenRouter, ollama, vLLM, OpenAI. Function-calling: tools -> tool_calls -> role:tool.
type openaiModel struct {
	baseURL, key, model string
	httpc               *http.Client
	tools               []oaiTool
	messages            []oaiMsg
}

type oaiMsg struct {
	Role       string        `json:"role"`
	Content    string        `json:"content"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

type oaiToolCall struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	Function oaiFunc `json:"function"`
}

type oaiFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type oaiTool struct {
	Type     string     `json:"type"`
	Function oaiFuncDef `json:"function"`
}

type oaiFuncDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// NewOpenAI builds an OpenAI-compatible tool-use model. baseURL is the endpoint
// (e.g. https://openrouter.ai/api/v1); key is the bearer token.
func NewOpenAI(key, modelID, baseURL, system, input string, tools []Tool, timeout time.Duration) ToolModel {
	ot := make([]oaiTool, 0, len(tools))
	for _, t := range tools {
		params := t.Schema
		if len(params) == 0 {
			params = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		ot = append(ot, oaiTool{Type: "function", Function: oaiFuncDef{
			Name: t.Name, Description: t.Description, Parameters: params,
		}})
	}
	msgs := make([]oaiMsg, 0, 2)
	if system != "" {
		msgs = append(msgs, oaiMsg{Role: "system", Content: system})
	}
	msgs = append(msgs, oaiMsg{Role: "user", Content: input})
	return &openaiModel{
		baseURL: strings.TrimRight(baseURL, "/"), key: key, model: modelID,
		httpc: &http.Client{Timeout: timeout}, tools: ot, messages: msgs,
	}
}

func (o *openaiModel) Name() string { return "openai:" + o.model }

func (o *openaiModel) Propose(ctx context.Context, results []ToolResult) (Turn, error) {
	for _, r := range results {
		o.messages = append(o.messages, oaiMsg{Role: "tool", ToolCallID: r.CallID, Content: r.Content})
	}
	body, _ := json.Marshal(map[string]any{
		"model": o.model, "messages": o.messages, "tools": o.tools, "tool_choice": "auto", "max_tokens": 4096,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Turn{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.key)
	resp, err := o.httpc.Do(req)
	if err != nil {
		return Turn{}, fmt.Errorf("openai: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Choices []struct {
			Message struct {
				Content   string        `json:"content"`
				ToolCalls []oaiToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message  string          `json:"message"`
			Code     any             `json:"code"`
			Metadata json.RawMessage `json:"metadata"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Turn{}, fmt.Errorf("openai decode (HTTP %d): %w — body: %.300s", resp.StatusCode, err, string(raw))
	}
	if out.Error != nil {
		return Turn{}, fmt.Errorf("openai (HTTP %d, code %v): %s %s", resp.StatusCode, out.Error.Code, out.Error.Message, string(out.Error.Metadata))
	}
	if len(out.Choices) == 0 {
		return Turn{}, fmt.Errorf("openai: empty response")
	}
	msg := out.Choices[0].Message
	calls := msg.ToolCalls
	if len(calls) == 0 {
		// Fallback: many open models (Hermes/Qwen/nemotron-style) emit tool calls as
		// <tool_call>{"name":..,"arguments":{..}}</tool_call> TEXT that OpenRouter did not
		// normalize into the tool_calls field. Parse them so those models work too.
		calls = parseTextToolCalls(msg.Content)
	}
	// record the assistant turn WITH the (structured or recovered) tool_calls so the tool
	// results in the next round match a preceding call (protocol stays valid).
	o.messages = append(o.messages, oaiMsg{Role: "assistant", Content: msg.Content, ToolCalls: calls})

	turn := Turn{Text: msg.Content}
	for _, tc := range calls {
		turn.Calls = append(turn.Calls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Input: json.RawMessage(tc.Function.Arguments)})
	}
	return turn, nil
}

// parseTextToolCalls recovers tool calls that a model emitted as literal
// <tool_call>{...}</tool_call> text (Hermes/Qwen/nemotron format) instead of the
// structured tool_calls field. Each block's JSON is {"name":..,"arguments":{..}}.
func parseTextToolCalls(content string) []oaiToolCall {
	var out []oaiToolCall
	rest := content
	for {
		s := strings.Index(rest, "<tool_call>")
		if s < 0 {
			break
		}
		rest = rest[s+len("<tool_call>"):]
		e := strings.Index(rest, "</tool_call>")
		if e < 0 {
			break
		}
		block := strings.TrimSpace(rest[:e])
		rest = rest[e+len("</tool_call>"):]
		var call struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if json.Unmarshal([]byte(block), &call) == nil && call.Name != "" {
			args := string(call.Arguments)
			if args == "" {
				args = "{}"
			}
			out = append(out, oaiToolCall{
				ID:       fmt.Sprintf("call_%d", len(out)+1),
				Type:     "function",
				Function: oaiFunc{Name: call.Name, Arguments: args},
			})
		}
	}
	return out
}
