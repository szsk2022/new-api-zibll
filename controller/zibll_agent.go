package controller

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/oauth"
	"github.com/gin-gonic/gin"
)

// ----------------------------------------------------------------------------
// Zibll agent login settings (root only)
// ----------------------------------------------------------------------------

type zibllAgentSettingsRequest struct {
	ServerAddress string   `json:"server_address"`
	Key           string   `json:"key"`
	Types         []string `json:"types"`
}

type zibllAgentTypeStatus struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Icon    string `json:"icon"`
	Enabled bool   `json:"enabled"`
	QRCode  bool   `json:"qrcode"`
}

func zibllAgentTypeStatuses() []zibllAgentTypeStatus {
	enabled := make(map[string]bool)
	for _, typeName := range strings.Split(common.ZibllAgentTypes, ",") {
		typeName = strings.TrimSpace(strings.ToLower(typeName))
		if typeName != "" {
			enabled[typeName] = true
		}
	}
	statuses := make([]zibllAgentTypeStatus, 0, len(oauth.ZibllLoginTypes))
	for _, loginType := range oauth.ZibllLoginTypes {
		statuses = append(statuses, zibllAgentTypeStatus{
			Type:    loginType.Type,
			Name:    loginType.Name,
			Icon:    loginType.Icon,
			Enabled: enabled[loginType.Type],
			QRCode:  loginType.QRCodeFlow,
		})
	}
	return statuses
}

// GetZibllAgentSettings returns the agent server configuration. The shared
// key never leaves the server; only whether it is configured.
func GetZibllAgentSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"server_address": common.ZibllAgentServerAddress,
			"key_configured": strings.TrimSpace(common.ZibllAgentKey) != "",
			"types":          zibllAgentTypeStatuses(),
		},
	})
}

// UpdateZibllAgentSettings saves the master-site address, the shared key and
// the enabled login types, then reconciles the provider rows with the registry.
func UpdateZibllAgentSettings(c *gin.Context) {
	var request zibllAgentSettingsRequest
	if err := common.DecodeJson(c.Request.Body, &request); err != nil {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	serverAddress := strings.TrimSpace(request.ServerAddress)
	key := strings.TrimSpace(request.Key)
	if serverAddress == "" {
		common.ApiErrorT(c, "The Zibll agent server address is required")
		return
	}
	parsed, err := url.Parse(serverAddress)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		common.ApiErrorT(c, "The Zibll agent server address must be a valid http(s) URL")
		return
	}
	if key == "" && strings.TrimSpace(common.ZibllAgentKey) == "" {
		common.ApiErrorT(c, "The Zibll agent shared key is required")
		return
	}
	seen := make(map[string]bool)
	for _, typeName := range request.Types {
		typeName = strings.TrimSpace(strings.ToLower(typeName))
		if typeName == "" {
			continue
		}
		if _, ok := oauth.GetZibllLoginType(typeName); !ok {
			common.ApiErrorT(c, "Unknown Zibll login type {{type}}", map[string]any{"type": typeName})
			return
		}
		seen[typeName] = true
	}
	enabledTypes := make([]string, 0, len(seen))
	for _, loginType := range oauth.ZibllLoginTypes {
		if seen[loginType.Type] {
			enabledTypes = append(enabledTypes, loginType.Type)
		}
	}

	// An empty key keeps the configured one so the UI can submit partial edits.
	if key != "" {
		if err := model.UpdateOption("ZibllAgentKey", key); err != nil {
			common.ApiError(c, err)
			return
		}
	}
	if err := model.UpdateOption("ZibllAgentServerAddress", serverAddress); err != nil {
		common.ApiError(c, err)
		return
	}
	if err := model.UpdateOption("ZibllAgentTypes", strings.Join(enabledTypes, ",")); err != nil {
		common.ApiError(c, err)
		return
	}
	if err := oauth.SyncZibllProviders(); err != nil {
		common.ApiError(c, err)
		return
	}
	if err := oauth.ReloadCustomProviders(); err != nil {
		common.SysError(common.LogText("Failed to reload OAuth providers after Zibll agent update: %s", err.Error()))
	}
	// 出于安全考虑只记录动作，不记录配置值（通讯密钥等敏感信息）。
	recordManageAudit(c, "zibll_agent.update", map[string]any{
		"enabled_types": strings.Join(enabledTypes, ","),
	})
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"server_address": common.ZibllAgentServerAddress,
			"key_configured": strings.TrimSpace(common.ZibllAgentKey) != "",
			"types":          zibllAgentTypeStatuses(),
		},
	})
}

// ----------------------------------------------------------------------------
// Signed identity callback (the master site's agent_back_url target)
// ----------------------------------------------------------------------------

// ZibllCallbackExchange consumes the signed identity redirect. The web console
// callback page forwards the master site's query parameters here untouched;
// this handler just routes them through the standard OAuth pipeline.
func ZibllCallbackExchange(c *gin.Context) {
	slug := c.Param("slug")
	provider := oauth.GetProvider(slug)
	if provider == nil {
		writeAccountStatusError(c, http.StatusBadRequest, "Unknown OAuth provider")
		return
	}
	if _, ok := provider.(*oauth.ZibllAgentProvider); !ok {
		writeAccountStatusError(c, http.StatusBadRequest, "Unknown OAuth provider")
		return
	}
	c.Params = append(c.Params, gin.Param{Key: "provider", Value: slug})
	HandleOAuth(c)
}

// ----------------------------------------------------------------------------
// weixingzh (WeChat official account) QR code / verification code flow
// ----------------------------------------------------------------------------

const zibllGZHSlug = oauth.ZibllSlugPrefix + "weixingzh"

func zibllGZHFlow(state string) (*model.AuthFlow, error) {
	return model.GetAuthFlow(state, model.AuthFlowMatch{
		Purpose:  model.AuthFlowPurposeOAuth,
		Provider: zibllGZHSlug,
	})
}

// ZibllGZHStart fetches the official-account QR code from the master site and
// remembers the master-side state on the auth flow for the polling endpoint.
func ZibllGZHStart(c *gin.Context) {
	state := c.Query("state")
	if state == "" {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	if _, err := zibllGZHFlow(state); err != nil {
		writeAccountStatusError(c, http.StatusForbidden, "State parameter is empty or mismatched")
		return
	}
	agentBackURL := oauth.ZibllAgentBackURL(zibllGZHSlug, state)
	qrURL, qrState, err := oauth.ZibllFetchGZHQRCode(agentBackURL)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	var payload oauthFlowPayload
	flow, err := zibllGZHFlow(state)
	if err == nil {
		_ = common.UnmarshalJsonStr(flow.Payload, &payload)
	}
	payload.Zibll = &ZibllFlowExtra{QRState: qrState}
	if payloadBytes, err := common.Marshal(payload); err == nil {
		if err := model.UpdateAuthFlowPayload(state, model.AuthFlowMatch{
			Purpose:  model.AuthFlowPurposeOAuth,
			Provider: zibllGZHSlug,
		}, string(payloadBytes)); err != nil {
			common.ApiError(c, err)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"qr_url": qrURL,
		},
	})
}

// ZibllGZHCheck polls the master site for the QR scan result. Once the scan
// succeeds it returns the goto URL the browser must follow to finish login.
func ZibllGZHCheck(c *gin.Context) {
	state := c.Param("state")
	if state == "" {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	flow, err := zibllGZHFlow(state)
	if err != nil {
		writeAccountStatusError(c, http.StatusForbidden, "State parameter is empty or mismatched")
		return
	}
	var payload oauthFlowPayload
	if err := common.UnmarshalJsonStr(flow.Payload, &payload); err != nil || payload.Zibll == nil || payload.Zibll.QRState == "" {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	agentBackURL := oauth.ZibllAgentBackURL(zibllGZHSlug, state)
	gotoURL, waiting, err := oauth.ZibllGZHCheckLogin(payload.Zibll.QRState, agentBackURL)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if waiting {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "",
			"data": gin.H{
				"status": "waiting",
			},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"status": "done",
			"goto":   gotoURL,
		},
	})
}

// ZibllGZHCode exchanges the verification code sent to the official account
// for the login goto URL.
func ZibllGZHCode(c *gin.Context) {
	state := c.Query("state")
	code := strings.TrimSpace(c.Query("code"))
	if state == "" || code == "" {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	if _, err := zibllGZHFlow(state); err != nil {
		writeAccountStatusError(c, http.StatusForbidden, "State parameter is empty or mismatched")
		return
	}
	agentBackURL := oauth.ZibllAgentBackURL(zibllGZHSlug, state)
	gotoURL, err := oauth.ZibllGZHCodeLogin(code, agentBackURL)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"status": "done",
			"goto":   gotoURL,
		},
	})
}
