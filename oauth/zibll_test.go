package oauth

import (
	"strings"
	"testing"
)

// The golden signatures below were produced by PHP 8.3 running the exact sign
// semantics of the Zibll theme's oauth/sdk/agent.php (implode of $_GET values
// in query order, nested arrays rendering as "Array", duplicated keys keeping
// the last value, then appending the shared key and md5).
const zibllTestKey = "test_shared_key_12345"

func TestZibllVerifyCallbackSignGolden(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  string
	}{
		{
			name:  "weixin_callback",
			query: "type=weixin&openid=o6_bmjrPTlm6_2sgVt7hMZOPfL2M&name=%E5%BC%A0%E4%B8%89&avatar=https%3A%2F%2Fthirdwx.qlogo.cn%2Fmmopen%2FvitajtzFs76.png%2F132&description=&getUserInfo%5Bopenid%5D=o6_bmjrPTlm6_2sgVt7hMZOPfL2M&getUserInfo%5Bnickname%5D=%E5%BC%A0%E4%B8%89&getUserInfo%5Bheadimgurl%5D=https%3A%2F%2Fthirdwx.qlogo.cn%2F132&oauth_rurl=https%3A%2F%2Fconsole.example.com%2Fdashboard",
			want:  "1f1308c45f2091e0e782bb2480e21460",
		},
		{
			name:  "weixin_callback_plain",
			query: "type=weixin&openid=oABC123&name=Nick+Name&avatar=https%3A%2F%2Fqlogo.cn%2Fa.png&description=&getUserInfo%5Bnickname%5D=Nick+Name",
			want:  "8323ea1ff944b9ab603441a93d73a740",
		},
		{
			name:  "qq_callback",
			query: "type=qq&openid=QQOPENID123&name=QQUser&avatar=&description=desc+text&sign_ignore=1",
			want:  "ae7eaf6180d7bbdb938e3c6141449df4",
		},
		{
			name:  "dup_key",
			query: "type=github&openid=gh1&name=a&name=b&sign_x=1",
			want:  "d229a9bb4af879fc3f36a2f9921a7285",
		},
		{
			name:  "gzh_goto",
			query: "token=eyJhbGciOiJIUzI1NiJ9.xxx&action=login&login_nonce=0123456789abcdef0123456789abcdef&agent_back_url=https%3A%2F%2Fnewapi.example.com%2Foauth%2Fzibll%2Fzibll-weixingzh%2Fflowstate123",
			want:  "2743da26a860f58c13d7c45c56775511",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Our extractor must reproduce the PHP golden signature exactly.
			concat, _, err := zibllExtractSignedValues(tc.query)
			if err != nil {
				t.Fatalf("extract failed for %s: %v", tc.name, err)
			}
			got := zibllSign(concat, zibllTestKey)
			if got != tc.want {
				t.Fatalf("sign mismatch for %s: got %s, php golden %s", tc.name, got, tc.want)
			}
			// The verifier must accept the query with the golden signature
			// appended, even when our own flow state is appended afterwards.
			signed := tc.query + "&sign=" + tc.want
			withState := signed + "&state=someflowstate"
			if err := zibllVerifyCallbackSign(withState, zibllTestKey); err != nil {
				t.Fatalf("verify failed for %s: %v", tc.name, err)
			}
			if err := zibllVerifyCallbackSign(signed, zibllTestKey); err != nil {
				t.Fatalf("verify failed for %s: %v", tc.name, err)
			}
			// Tampered query must fail.
			tampered := strings.Replace(signed, "&sign=", "&openid=EVIL&sign=", 1)
			if err := zibllVerifyCallbackSign(tampered, zibllTestKey); err == nil {
				t.Fatalf("tampered query unexpectedly verified for %s", tc.name)
			}
			// Wrong key must fail.
			if err := zibllVerifyCallbackSign(signed, "another_key"); err == nil {
				t.Fatalf("wrong key unexpectedly verified for %s", tc.name)
			}
		})
	}
}

func TestZibllParseCallbackIdentity(t *testing.T) {
	// Field extraction from a signed callback (signature verified separately).
	query := "type=weixin&openid=o6_bmjrPTlm6_2sgVt7hMZOPfL2M&name=%E5%BC%A0%E4%B8%89&avatar=&description=&getUserInfo%5Bnickname%5D=%E5%BC%A0%E4%B8%89"
	values := zibllParseQueryValues(query)
	if values["type"] != "weixin" {
		t.Fatalf("type = %q", values["type"])
	}
	if values["openid"] != "o6_bmjrPTlm6_2sgVt7hMZOPfL2M" {
		t.Fatalf("openid = %q", values["openid"])
	}
	if values["name"] != "张三" {
		t.Fatalf("name = %q", values["name"])
	}
	if values["getUserInfo[nickname]"] != "张三" {
		t.Fatalf("nested value = %q", values["getUserInfo[nickname]"])
	}
}

func TestZibllSignOrderingGolden(t *testing.T) {
	// Requests we SEND must sign in the theme's insertion order. Each case
	// pairs the ordered values with the PHP golden md5 from the same input.
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{
			name:   "auth_url",
			values: []string{"authstate999", "https://newapi.example.com/oauth/zibll/zibll-weixin/authstate999"},
			want:   "e8f310d26f46d180b90647c76e6a4860",
		},
		{
			name:   "check_callback",
			values: []string{"qrstate777", "check_callback", "https://newapi.example.com/oauth/zibll/zibll-weixingzh/flowstate123"},
			want:   "a7e22659122fb826097ee1eb5c84ef05",
		},
		{
			name:   "code_check",
			values: []string{"code_check", "1234", "https://newapi.example.com/oauth/zibll/zibll-weixingzh/flowstate123"},
			want:   "5b9e588e217d931b5efb3f812aa386bb",
		},
		{
			name:   "gzh_goto",
			values: []string{"eyJhbGciOiJIUzI1NiJ9.xxx", "login", "0123456789abcdef0123456789abcdef", "https://newapi.example.com/oauth/zibll/zibll-weixingzh/flowstate123"},
			want:   "2743da26a860f58c13d7c45c56775511",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := zibllSign(tc.values, zibllTestKey)
			if got != tc.want {
				t.Fatalf("sign mismatch for %s: got %s, php golden %s", tc.name, got, tc.want)
			}
		})
	}
}
