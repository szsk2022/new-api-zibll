package oauth

import (
	"context"
	crand "crypto/rand"
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
)

// Zibll agent login protocol (ZibllProxyLogin).
//
// new-api acts as a Zibll agent login client (the role of a Zibll sub-site), and the
// configured Zibll master site runs as the agent login server, which actually completes
// the real OAuth for WeChat / QQ / GitHub / etc., then brings the user identity back to
// new-api as an md5-signed redirect.
//
// Protocol flow (consistent with the theme's oauth/sdk/agent.php):
//  1. Client redirects the browser to `{master}/oauth/{type}?state=..&agent_back_url=..&sign`
//     sign = md5(concat(param values in order) + communication key)
//  2. Master completes the real OAuth, then 302 redirects to agent_back_url with
//     `type/openid/name/avatar/...` parameters attached, signed the same way.
//  3. Client verifies the signature and completes login/binding.
//
// The weixingzh (WeChat official account) type differs from other types: the master site first
// returns a QR code, and the client polls `callback?action=check_callback` / `code_check`,
// and after getting a one-time token, guides the browser to the master's goto address, which then
// redirects back to agent_back_url with the signed identity.

const (
	// ZibllProviderKind marks CustomOAuthProvider rows managed by the Zibll
	// agent settings rather than the generic custom OAuth admin UI.
	ZibllProviderKind = "zibll"
	// ZibllSlugPrefix is the slug prefix shared by all Zibll agent providers.
	ZibllSlugPrefix = "zibll-"

	// zibllGZHType is the WeChat official account login type, which needs the
	// QR code / verification code sub-flows instead of a plain redirect.
	zibllGZHType = "weixingzh"
)

// ZibllLoginType describes one proxied login method offered by the master site.
type ZibllLoginType struct {
	Type        string // protocol type, matches the Zibll oauth_s option (e.g. "weixin")
	Name        string // display name shown on the login page
	Icon        string // icon key resolved by the web console brand icons
	QRCodeFlow  bool   // weixingzh: QR code / verification code flow instead of redirect
}

// ZibllLoginTypes lists every login method the Zibll agent client supports.
// The list mirrors the theme's oauth_s options (inc/options/admin-options.php).
// 国内渠道显示名使用中文（与子比主题一致）；产品名本身是英文/字母的
// （QQ、Gitee、GitHub、Google 等海外渠道）保持原样。
var ZibllLoginTypes = []ZibllLoginType{
	{Type: "weixin", Name: "微信", Icon: "zibll-weixin"},
	{Type: "weixingzh", Name: "微信公众号", Icon: "zibll-weixingzh", QRCodeFlow: true},
	{Type: "qq", Name: "QQ", Icon: "zibll-qq"},
	{Type: "weibo", Name: "微博", Icon: "zibll-weibo"},
	{Type: "douyin", Name: "抖音", Icon: "zibll-douyin"},
	{Type: "github", Name: "GitHub", Icon: "zibll-github"},
	{Type: "gitee", Name: "Gitee", Icon: "zibll-gitee"},
	{Type: "baidu", Name: "百度", Icon: "zibll-baidu"},
	{Type: "alipay", Name: "支付宝", Icon: "zibll-alipay"},
	{Type: "google", Name: "Google", Icon: "zibll-google"},
	{Type: "microsoft", Name: "Microsoft", Icon: "zibll-microsoft"},
	{Type: "facebook", Name: "Facebook", Icon: "zibll-facebook"},
	{Type: "twitter", Name: "Twitter", Icon: "zibll-twitter"},
	{Type: "apple", Name: "Apple", Icon: "zibll-apple"},
}

// GetZibllLoginType returns the type metadata for a protocol type or slug.
func GetZibllLoginType(key string) (ZibllLoginType, bool) {
	key = strings.TrimPrefix(strings.ToLower(key), ZibllSlugPrefix)
	for _, t := range ZibllLoginTypes {
		if t.Type == key {
			return t, true
		}
	}
	return ZibllLoginType{}, false
}

// ZibllServerConfigured reports whether the agent server is configured.
func ZibllServerConfigured() bool {
	return strings.TrimSpace(common.ZibllAgentServerAddress) != "" &&
		strings.TrimSpace(common.ZibllAgentKey) != ""
}

func zibllServerBase() string {
	return strings.TrimRight(strings.TrimSpace(common.ZibllAgentServerAddress), "/")
}

func zibllKey() string {
	return strings.TrimSpace(common.ZibllAgentKey)
}

// zibllSign computes the Zibll agent signature: md5(concat(values in order) + key).
// It matches \agent\OAuth2::sign in the theme's oauth/sdk/agent.php, which
// concatenates the parameter values in insertion order and appends the shared key.
func zibllSign(values []string, key string) string {
	sum := md5.Sum([]byte(strings.Join(values, "") + key))
	return hex.EncodeToString(sum[:])
}

// zibllBuildQuery renders an ordered query string (PHP http_build_query order
// matters: the master site signs over $_REQUEST in query-string order).
func zibllBuildQuery(pairs [][2]string) string {
	parts := make([]string, 0, len(pairs))
	for _, kv := range pairs {
		parts = append(parts, url.QueryEscape(kv[0])+"="+url.QueryEscape(kv[1]))
	}
	return strings.Join(parts, "&")
}

// ZibllBuildAuthURL builds the signed redirect URL towards the master site's
// `/oauth/{type}` login page.
func ZibllBuildAuthURL(loginType string, state string, agentBackURL string) (string, error) {
	base := zibllServerBase()
	if base == "" || zibllKey() == "" {
		return "", errors.New("zibll agent server is not configured")
	}
	sign := zibllSign([]string{state, agentBackURL}, zibllKey())
	query := zibllBuildQuery([][2]string{
		{"state", state},
		{"agent_back_url", agentBackURL},
		{"sign", sign},
	})
	return base + "/oauth/" + loginType + "?" + query, nil
}

// zibllCallbackAPIPath is the backend endpoint that consumes the signed
// identity redirect. The browser lands on the frontend page which forwards
// the identity parameters here.
const zibllCallbackAPIPath = "/api/oauth/zibll/callback/"

// ZibllAgentBackURL builds the URL the master site redirects back to for a flow.
func ZibllAgentBackURL(slug string, state string) string {
	return strings.TrimRight(system_setting.ServerAddress, "/") + "/oauth/zibll/" + slug + "/" + state
}

// zibllExtractSignedValues mirrors how PHP builds $_GET and implode for the
// Zibll signature: values decoded, in query order, `getUserInfo[...]` entries
// folded into one array (implode renders the literal "Array"), duplicated
// keys keeping the last value at their first position. `sign` and the
// client-side flow `state` are excluded. Returns the ordered value list and
// the signature found in the query.
func zibllExtractSignedValues(rawQuery string) ([]string, string, error) {
	type entry struct {
		value string
		array bool
	}
	var order []string // first-occurrence order of top-level keys
	values := make(map[string]*entry)
	sign := ""
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		rawKey, rawValue, hasValue := strings.Cut(part, "=")
		decodedKey, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, "", fmt.Errorf("bad callback key encoding: %w", err)
		}
		decodedValue := ""
		if hasValue {
			decodedValue, err = url.QueryUnescape(rawValue)
			if err != nil {
				return nil, "", fmt.Errorf("bad callback value encoding: %w", err)
			}
		}
		if decodedKey == "sign" {
			sign = decodedValue
			continue
		}
		if decodedKey == "state" {
			// new-api's own flow token appended by the console callback page;
			// never part of the master site's signed parameter set.
			continue
		}
		// PHP folds every `getUserInfo[...]` entry into the one `getUserInfo`
		// array at its first-occurrence position; canonicalise the key so all
		// variants share a single slot.
		mapKey := decodedKey
		isArray := strings.HasPrefix(decodedKey, "getUserInfo")
		if isArray {
			mapKey = "getUserInfo"
		}
		if existing, ok := values[mapKey]; ok {
			if isArray {
				existing.array = true // nested entries upgrade a scalar slot to an array
				continue
			}
			if existing.array {
				continue // array slot wins over a scalar duplicate in PHP implode order
			}
			existing.value = decodedValue // PHP keeps the last scalar value
			continue
		}
		values[mapKey] = &entry{value: decodedValue, array: isArray}
		order = append(order, mapKey)
	}
	concat := make([]string, 0, len(order))
	for _, name := range order {
		entry := values[name]
		if entry.array {
			// PHP implode over an array element renders the literal "Array".
			concat = append(concat, "Array")
			continue
		}
		concat = append(concat, entry.value)
	}
	return concat, sign, nil
}

// zibllVerifyCallbackSign verifies the signed identity redirect from the
// master site against the raw query string.
func zibllVerifyCallbackSign(rawQuery string, key string) error {
	if strings.TrimSpace(rawQuery) == "" {
		return errors.New("empty zibll callback query")
	}
	concat, sign, err := zibllExtractSignedValues(rawQuery)
	if err != nil {
		return err
	}
	if sign == "" {
		return errors.New("missing zibll callback signature")
	}
	expected := zibllSign(concat, key)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(sign)) != 1 {
		return errors.New("zibll callback signature verification failed")
	}
	return nil
}

// ZibllCallbackIdentity holds the verified identity fields of a signed redirect.
type ZibllCallbackIdentity struct {
	Type    string
	OpenID  string
	Name    string
	Avatar  string
	Detail  string
	RawURL  string
	Expires time.Time
}

// ZibllParseCallbackIdentity verifies the signature and extracts identity fields.
func ZibllParseCallbackIdentity(rawQuery string) (*ZibllCallbackIdentity, error) {
	if !ZibllServerConfigured() {
		return nil, errors.New("zibll agent server is not configured")
	}
	if err := zibllVerifyCallbackSign(rawQuery, zibllKey()); err != nil {
		return nil, err
	}
	values := zibllParseQueryValues(rawQuery)
	identity := &ZibllCallbackIdentity{
		Type:   values["type"],
		OpenID: values["openid"],
		Name:   values["name"],
		Avatar: values["avatar"],
		Detail: values["description"],
		RawURL: values["oauth_rurl"],
	}
	if identity.OpenID == "" {
		return nil, errors.New("zibll callback identity is missing openid")
	}
	return identity, nil
}

// zibllParseQueryValues returns decoded query values, last one wins.
func zibllParseQueryValues(rawQuery string) map[string]string {
	result := make(map[string]string)
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		rawKey, rawValue, hasValue := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			continue
		}
		value := ""
		if hasValue {
			if value, err = url.QueryUnescape(rawValue); err != nil {
				continue
			}
		}
		result[key] = value
	}
	return result
}

// ----------------------------------------------------------------------------
// weixingzh (WeChat official account) QR code / verification code sub-flows
// ----------------------------------------------------------------------------

// ZibllFetchGZHQRCode asks the master site for the official-account QR code.
// It mirrors the QR branch of the theme's oauth/agent/login.php: a POST to the
// signed auth URL returns {url, state} where `url` is the QR image link and
// `state` the master-side state required by the polling call.
func ZibllFetchGZHQRCode(agentBackURL string) (qrURL string, qrState string, err error) {
	base := zibllServerBase()
	if base == "" || zibllKey() == "" {
		return "", "", errors.New("zibll agent server is not configured")
	}
	authURL, err := ZibllBuildAuthURL(zibllGZHType, zibllRandomState(), agentBackURL)
	if err != nil {
		return "", "", err
	}
	result, err := zibllPostJSON(authURL)
	if err != nil {
		return "", "", err
	}
	qrURL, _ = result["url"].(string)
	qrState, _ = result["state"].(string)
	if qrURL == "" || qrState == "" {
		return "", "", errors.New("zibll agent returned an invalid QR code response")
	}
	return qrURL, qrState, nil
}

// ZibllGZHCheckLogin polls the master site for the scanned QR code result.
// Once the scan succeeds it returns the `goto` URL that walks the browser
// through the master's callback and back to our agent_back_url.
func ZibllGZHCheckLogin(qrState string, agentBackURL string) (gotoURL string, waiting bool, err error) {
	if qrState == "" || agentBackURL == "" {
		return "", false, errors.New("invalid zibll GZH check parameters")
	}
	sign := zibllSign([]string{qrState, "check_callback", agentBackURL}, zibllKey())
	checkURL := zibllServerBase() + "/oauth/" + zibllGZHType + "/callback?" + zibllBuildQuery([][2]string{
		{"state", qrState},
		{"action", "check_callback"},
		{"agent_back_url", agentBackURL},
		{"sign", sign},
	})
	result, err := zibllPostJSON(checkURL)
	if err != nil {
		return "", false, err
	}
	token, _ := result["token"].(string)
	if token == "" {
		return "", true, nil
	}
	gotoURL, err = ZibllBuildGZHLoginGoto(token, "login", agentBackURL)
	if err != nil {
		return "", false, err
	}
	return gotoURL, false, nil
}

// ZibllGZHCodeLogin exchanges the verification code sent to the official
// account for the login goto URL (theme action=code_check -> code_login).
func ZibllGZHCodeLogin(code string, agentBackURL string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", errors.New("zibll verification code is empty")
	}
	sign := zibllSign([]string{"code_check", code, agentBackURL}, zibllKey())
	checkURL := zibllServerBase() + "/oauth/" + zibllGZHType + "/callback?" + zibllBuildQuery([][2]string{
		{"action", "code_check"},
		{"code", code},
		{"agent_back_url", agentBackURL},
		{"sign", sign},
	})
	result, err := zibllPostJSON(checkURL)
	if err != nil {
		return "", err
	}
	token, _ := result["token"].(string)
	if token == "" {
		message, _ := result["msg"].(string)
		if message == "" {
			message = "verification code is incorrect or has expired"
		}
		return "", errors.New(message)
	}
	return ZibllBuildGZHLoginGoto(token, "code_login", agentBackURL)
}

// ZibllBuildGZHLoginGoto signs the one-time token into the master-side goto
// URL (token/action/login_nonce/agent_back_url order, matching getCallbackUrl).
func ZibllBuildGZHLoginGoto(token string, action string, agentBackURL string) (string, error) {
	nonceHex, err := zibllRandomHex(16)
	if err != nil {
		return "", err
	}
	sign := zibllSign([]string{token, action, nonceHex, agentBackURL}, zibllKey())
	return zibllServerBase() + "/oauth/" + zibllGZHType + "/callback?" + zibllBuildQuery([][2]string{
		{"token", token},
		{"action", action},
		{"login_nonce", nonceHex},
		{"agent_back_url", agentBackURL},
		{"sign", sign},
	}), nil
}

// zibllRandomState mimics the theme's md5(time+rand) flow state.
func zibllRandomState() string {
	random, err := zibllRandomHex(16)
	if err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	sum := md5.Sum([]byte(fmt.Sprintf("%d%s", time.Now().UnixNano(), random)))
	return hex.EncodeToString(sum[:])
}

// zibllRandomHex returns n random bytes hex encoded.
func zibllRandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := crand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// zibllPostJSON POSTs a signed protocol URL and decodes the JSON reply.
func zibllPostJSON(target string) (map[string]any, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodPost, target, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zibll agent request failed: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := common.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("zibll agent returned an invalid response: %w", err)
	}
	return result, nil
}

// ----------------------------------------------------------------------------
// Provider
// ----------------------------------------------------------------------------

// ZibllAuthorizationProvider is implemented by providers whose authorization
// redirect is built server-side (the signed master URL) instead of coming from
// the standard authorization_endpoint.
type ZibllAuthorizationProvider interface {
	Provider
	// BuildAuthorizationURL returns the signed master-site login URL for a flow.
	BuildAuthorizationURL(state string) (string, error)
	// IsQRCodeFlow reports the weixingzh QR/verification-code variant.
	IsQRCodeFlow() bool
}

// ZibllAgentProvider implements the Zibll agent login protocol on top of the
// generic custom provider machinery (bindings, audit, admin management).
type ZibllAgentProvider struct {
	config *model.CustomOAuthProvider
}

// NewZibllAgentProvider creates the provider from its configuration row.
func NewZibllAgentProvider(config *model.CustomOAuthProvider) *ZibllAgentProvider {
	return &ZibllAgentProvider{config: config}
}

func (p *ZibllAgentProvider) GetName() string {
	return p.config.Name
}

func (p *ZibllAgentProvider) IsEnabled() bool {
	return p.config.Enabled && ZibllServerConfigured()
}

func (p *ZibllAgentProvider) GetConfig() *model.CustomOAuthProvider {
	return p.config
}

func (p *ZibllAgentProvider) LoginType() string {
	return strings.TrimPrefix(p.config.ClientId, ZibllSlugPrefix)
}

// BuildAuthorizationURL implements ZibllAuthorizationProvider.
func (p *ZibllAgentProvider) BuildAuthorizationURL(state string) (string, error) {
	agentBackURL := ZibllAgentBackURL(p.config.Slug, state)
	return ZibllBuildAuthURL(p.LoginType(), state, agentBackURL)
}

// IsQRCodeFlow implements ZibllAuthorizationProvider.
func (p *ZibllAgentProvider) IsQRCodeFlow() bool {
	loginType, ok := GetZibllLoginType(p.LoginType())
	return ok && loginType.QRCodeFlow
}

// ExchangeToken consumes the signed identity redirect carried on the callback
// request. The Zibll protocol has no token endpoint; the signed parameters are
// the assertion, so they are serialized into the returned token for GetUserInfo.
func (p *ZibllAgentProvider) ExchangeToken(ctx context.Context, code string, c *gin.Context) (*OAuthToken, error) {
	identity, err := ZibllParseCallbackIdentity(c.Request.URL.RawQuery)
	if err != nil {
		logger.LogError(ctx, common.LogText("[OAuth-Zibll-%s] callback rejected: %s", p.config.Slug, err.Error()))
		return nil, NewOAuthErrorWithRaw(common.NewMessage(msgTokenFailed, map[string]any{"provider": p.config.Name}), err.Error())
	}
	loginType := p.LoginType()
	if identity.Type != loginType {
		logger.LogError(ctx, common.LogText("[OAuth-Zibll-%s] type mismatch: %s", p.config.Slug, identity.Type))
		return nil, NewOAuthErrorWithRaw(common.NewMessage(msgTokenFailed, map[string]any{"provider": p.config.Name}), "login type mismatch")
	}
	payload, err := common.Marshal(map[string]string{
		"openid":   identity.OpenID,
		"name":     identity.Name,
		"avatar":   identity.Avatar,
		"detail":   identity.Detail,
		"raw_url":  identity.RawURL,
		"lo_type":  identity.Type,
	})
	if err != nil {
		return nil, err
	}
	return &OAuthToken{AccessToken: string(payload), TokenType: "zibll-identity"}, nil
}

// GetUserInfo decodes the verified identity assertion.
func (p *ZibllAgentProvider) GetUserInfo(ctx context.Context, token *OAuthToken) (*OAuthUser, error) {
	var identity struct {
		OpenID  string `json:"openid"`
		Name    string `json:"name"`
		Avatar  string `json:"avatar"`
		Detail  string `json:"detail"`
		RawURL  string `json:"raw_url"`
		LOType  string `json:"lo_type"`
	}
	if err := common.UnmarshalJsonStr(token.AccessToken, &identity); err != nil || identity.OpenID == "" {
		logger.LogError(ctx, common.LogText("[OAuth-Zibll-%s] identity decode failed: %v", p.config.Slug, err))
		return nil, NewOAuthError(common.NewMessage(msgUserInfoEmpty, map[string]any{"provider": p.config.Name}))
	}
	return &OAuthUser{
		ProviderUserID: identity.OpenID,
		Username:       "",
		DisplayName:    identity.Name,
		Email:          "",
		Extra: map[string]any{
			"provider": p.config.Slug,
			"avatar":   identity.Avatar,
		},
	}, nil
}

func (p *ZibllAgentProvider) IsUserIDTaken(providerUserID string) bool {
	return model.IsProviderUserIdTaken(p.config.Id, providerUserID)
}

func (p *ZibllAgentProvider) FillUserByProviderID(user *model.User, providerUserID string) error {
	foundUser, err := model.GetUserByOAuthBinding(p.config.Id, providerUserID)
	if err != nil {
		return err
	}
	*user = *foundUser
	return nil
}

func (p *ZibllAgentProvider) SetProviderUserID(user *model.User, providerUserID string) {
	// Stored in user_oauth_bindings, handled by the OAuth controller transaction.
}

func (p *ZibllAgentProvider) GetProviderPrefix() string {
	return p.config.Slug + "_"
}

func (p *ZibllAgentProvider) ProviderUserIDColumn() string {
	return ""
}

func (p *ZibllAgentProvider) GetProviderId() int {
	return p.config.Id
}

// ----------------------------------------------------------------------------
// Settings sync
// ----------------------------------------------------------------------------

// SyncZibllProviders reconciles the custom provider rows with the enabled
// Zibll login types. Disabled types keep their rows (and user bindings) but
// are marked disabled.
func SyncZibllProviders() error {
	if !ZibllServerConfigured() {
		// Server removed: disable every managed row so logins stop immediately.
		rows, err := model.GetAllZibllProviders()
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Enabled {
				row.Enabled = false
				if err := model.UpdateCustomOAuthProvider(row); err != nil {
					return err
				}
			}
		}
		return nil
	}
	enabled := make(map[string]bool)
	for _, typeName := range strings.Split(common.ZibllAgentTypes, ",") {
		typeName = strings.TrimSpace(strings.ToLower(typeName))
		if typeName == "" {
			continue
		}
		if _, ok := GetZibllLoginType(typeName); ok {
			enabled[typeName] = true
		}
	}
	rows, err := model.GetAllZibllProviders()
	if err != nil {
		return err
	}
	existing := make(map[string]*model.CustomOAuthProvider, len(rows))
	for _, row := range rows {
		existing[strings.TrimPrefix(row.ClientId, ZibllSlugPrefix)] = row
	}
	for _, loginType := range ZibllLoginTypes {
		row, ok := existing[loginType.Type]
		shouldBeEnabled := enabled[loginType.Type]
		if !ok {
			if !shouldBeEnabled {
				continue
			}
			row = &model.CustomOAuthProvider{
				Name:         loginType.Name,
				Slug:         ZibllSlugPrefix + loginType.Type,
				Icon:         loginType.Icon,
				Enabled:      true,
				ClientId:     loginType.Type,
				ProviderKind: ZibllProviderKind,
			}
			if err := model.CreateCustomOAuthProvider(row); err != nil {
				return err
			}
			common.SysLog(common.LogText("Enabled Zibll agent login: %s (%s)", loginType.Name, row.Slug))
			continue
		}
		row.Name = loginType.Name
		row.Icon = loginType.Icon
		row.ProviderKind = ZibllProviderKind
		if row.Enabled != shouldBeEnabled {
			row.Enabled = shouldBeEnabled
		}
		if err := model.UpdateCustomOAuthProvider(row); err != nil {
			return err
		}
	}
	return nil
}
