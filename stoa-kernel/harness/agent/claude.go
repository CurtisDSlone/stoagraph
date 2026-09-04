package agent

// file-kw: adapter claude anthropic tool-use proposer translate mcp-tools-to-provider-schema

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

type claudeModel struct {
	client   anthropic.Client
	model    anthropic.Model
	system   string
	tools    []anthropic.ToolUnionParam
	messages []anthropic.MessageParam
}

// NewClaude builds a Claude tool-use model over the Anthropic Messages API. baseURL is an
// optional endpoint override; key is the API key.
func NewClaude(key, modelID, baseURL, system, input string, tools []Tool, timeout time.Duration) ToolModel {
	// The SDK's default client has its own timeout; override it so a model behind a slow
	// gateway is configurable rather than unusable.
	opts := []option.RequestOption{option.WithAPIKey(key), option.WithHTTPClient(&http.Client{Timeout: timeout})}
	if baseURL != "" {
		opts = append(opts, option.WithBaseURL(baseURL))
	}
	at := make([]anthropic.ToolUnionParam, 0, len(tools))
	for _, t := range tools {
		at = append(at, anthropic.ToolUnionParam{OfTool: &anthropic.ToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: anthropicSchema(t.Schema),
		}})
	}
	return &claudeModel{
		client:   anthropic.NewClient(opts...),
		model:    anthropic.Model(modelID),
		system:   system,
		tools:    at,
		messages: []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(input))},
	}
}

func (c *claudeModel) Name() string { return "claude:" + string(c.model) }

func (c *claudeModel) Propose(ctx context.Context, results []ToolResult) (Turn, error) {
	if len(results) > 0 {
		blocks := make([]anthropic.ContentBlockParamUnion, 0, len(results))
		for _, r := range results {
			blocks = append(blocks, anthropic.NewToolResultBlock(r.CallID, r.Content, r.IsError))
		}
		c.messages = append(c.messages, anthropic.NewUserMessage(blocks...))
	}
	params := anthropic.MessageNewParams{
		Model:     c.model,
		MaxTokens: 4096,
		Messages:  c.messages,
		Tools:     c.tools,
	}
	if c.system != "" {
		params.System = []anthropic.TextBlockParam{{Text: c.system}}
	}
	resp, err := c.client.Messages.New(ctx, params)
	if err != nil {
		return Turn{}, fmt.Errorf("claude: %w", err)
	}
	if resp.StopReason == anthropic.StopReasonRefusal {
		return Turn{}, fmt.Errorf("claude declined (refusal)")
	}
	c.messages = append(c.messages, resp.ToParam())

	var turn Turn
	for _, block := range resp.Content {
		switch b := block.AsAny().(type) {
		case anthropic.TextBlock:
			turn.Text += b.Text
		case anthropic.ToolUseBlock:
			turn.Calls = append(turn.Calls, ToolCall{ID: b.ID, Name: b.Name, Input: b.Input})
		}
	}
	return turn, nil
}

func anthropicSchema(raw json.RawMessage) anthropic.ToolInputSchemaParam {
	out := anthropic.ToolInputSchemaParam{}
	var m map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return out
	}
	out.Properties = m["properties"]
	if req, ok := m["required"].([]any); ok {
		for _, r := range req {
			out.Required = append(out.Required, fmt.Sprint(r))
		}
	}
	return out
}
