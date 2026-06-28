package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"aSuspect/shared"
)

// PasswordAuth logs in with username and password.
// Credentials are prompted interactively.
type PasswordAuth struct{}

// Login prompts for credentials and performs the password auth step.
func (a PasswordAuth) Login(s *Session) error {
	// Find the password auth domain from server config.
	domain := "local"
	if s.authConfigData != nil {
		for _, m := range s.authConfigData.AuthServerInfoList {
			if m.AuthType == "auth/psw" && m.LoginDomain != "" {
				domain = m.LoginDomain
				break
			}
		}
	}

	var username, password string
	fmt.Print("Username: ")
	fmt.Scanln(&username)
	fmt.Print("Password: ")
	fmt.Scanln(&password)

	return withCaptcha(s, func(captchaCode string) (int, error) {
		return s.loginPsw(username, password, domain, captchaCode)
	})
}

// loginPsw POSTs encrypted credentials to /passport/v1/auth/psw.
func (s *Session) loginPsw(username, password, loginDomain, graphCheckCode string) (int, error) {
	encrypted, err := s.EncryptPassword(password)
	if err != nil {
		return 0, err
	}

	data := map[string]interface{}{
		"username":    username + "@" + loginDomain,
		"password":    encrypted,
		"rememberPwd": "0",
	}
	if graphCheckCode != "" {
		data["graphCheckCode"] = graphCheckCode
	}

	payload, _ := json.Marshal(data)

	q := sharedParams(nil)
	u := fmt.Sprintf("%s/passport/v1/auth/psw?%s", s.baseURL(), q.Encode())
	req, _ := http.NewRequest("POST", u, strings.NewReader(string(payload)))
	req.Header.Set("User-Agent", shared.UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-env", s.env)
	req.Header.Set("x-sdp-traceid", randSdpID())

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var v struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Ticket               string `json:"ticket"`
			GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return 0, fmt.Errorf("parse psw response: %w", err)
	}
	if v.Code != 0 {
		return 0, fmt.Errorf("password login: code=%d %s", v.Code, v.Message)
	}

	if v.Data.Ticket != "" {
		s.ticket = v.Data.Ticket
	}
	return v.Data.GraphCheckCodeEnable, nil
}

// ── Captcha ──────────────────────────────────────────────────────────────────

// withCaptcha handles the captcha retry loop for a login operation.
func withCaptcha(s *Session, process func(captchaCode string) (int, error)) error {
	graphCheckCodeEnable, err := process("")
	if err != nil {
		return err
	}

	for attempt := 1; graphCheckCodeEnable == 1 && attempt <= 5; attempt++ {
		fmt.Printf("\nCaptcha required (attempt %d/5)\n", attempt)

		// Fetch captcha image.
		imgData, err := s.fetchCaptcha()
		if err != nil {
			return fmt.Errorf("fetch captcha: %w", err)
		}

		// Refresh auth config (server may have rotated CSRF/keys).
		if _, err := s.FetchAuthConfig(); err != nil {
			return fmt.Errorf("refresh auth config: %w", err)
		}

		// Save image.
		imgPath := fmt.Sprintf("captcha_%d.jpg", attempt)
		if err := os.WriteFile(imgPath, imgData, 0644); err != nil {
			return fmt.Errorf("save captcha: %w", err)
		}
		fmt.Printf("Captcha saved to %s\n", imgPath)

		// Prompt user.
		var rawInput string
		fmt.Print("Enter captcha JSON (coordinates format): ")
		fmt.Scanln(&rawInput)

		captchaCode, err := canonicalCaptcha(rawInput, imgData)
		if err != nil {
			return fmt.Errorf("captcha input: %w", err)
		}

		graphCheckCodeEnable, err = process(captchaCode)
		if err != nil {
			return err
		}

		if graphCheckCodeEnable == 0 {
			return nil
		}
		fmt.Printf("Captcha verification failed, retrying...\n")
	}

	if graphCheckCodeEnable != 0 {
		return fmt.Errorf("captcha verification failed after 5 attempts")
	}
	return nil
}

func (s *Session) fetchCaptcha() ([]byte, error) {
	u := fmt.Sprintf("%s/passport/v1/public/checkCode?rnd=1", s.baseURL())
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", "image/webp,image/apng,image/*,*/*;q=0.8")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func canonicalCaptcha(rawInput string, imgData []byte) (string, error) {
	rawInput = strings.TrimSpace(rawInput)

	// Accept three formats:
	// 1. {"coordinates": [[x,y],...], "width": W, "height": H}
	// 2. [{"x":X, "y":Y}, ...]
	// 3. [[x,y], ...]

	var obj map[string]interface{}
	if json.Unmarshal([]byte(rawInput), &obj) == nil {
		if _, ok := obj["coordinates"]; ok {
			b, _ := json.Marshal(obj)
			return string(b), nil
		}
	}

	var arr []interface{}
	if json.Unmarshal([]byte(rawInput), &arr) == nil && len(arr) > 0 {
		switch arr[0].(type) {
		case map[string]interface{}:
			// Format 2: [{"x":X, "y":Y}, ...]
			coords := make([][]int, 0, len(arr))
			for _, item := range arr {
				m := item.(map[string]interface{})
				coords = append(coords, []int{
					int(m["x"].(float64)),
					int(m["y"].(float64)),
				})
			}
			result := map[string]interface{}{
				"coordinates": coords,
				"width":       jpegDim(imgData, 7),
				"height":      jpegDim(imgData, 5),
			}
			b, _ := json.Marshal(result)
			return string(b), nil

		case []interface{}:
			// Format 3: [[x,y], ...]
			coords := make([][]int, 0, len(arr))
			for _, item := range arr {
				pair := item.([]interface{})
				coords = append(coords, []int{
					int(pair[0].(float64)),
					int(pair[1].(float64)),
				})
			}
			result := map[string]interface{}{
				"coordinates": coords,
				"width":       jpegDim(imgData, 7),
				"height":      jpegDim(imgData, 5),
			}
			b, _ := json.Marshal(result)
			return string(b), nil
		}
	}

	return "", fmt.Errorf("unrecognized captcha format: %s", rawInput)
}

// jpegDim extracts width or height from a JPEG SOF0 marker.
func jpegDim(data []byte, offset int) int {
	for i := 0; i < len(data)-9; i++ {
		if data[i] == 0xFF && data[i+1] == 0xC0 {
			return int(data[i+offset])<<8 | int(data[i+offset+1])
		}
	}
	return 300 // fallback
}
