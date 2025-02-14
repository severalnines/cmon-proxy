package whoami

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	UserName string   `json:"user_name"`
	Groups   []string `json:"groups"`
}

func GetUserInfo(whoamiURL, cmonSID string, client *http.Client) (*User, error) {
	payload := map[string]string{"operation": "whoAmI"}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", whoamiURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "cmon-sid", Value: cmonSID})

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("whoami request failed with status: %d", resp.StatusCode)
	}

	var userResp struct {
		User struct {
			UserName string `json:"user_name"`
			Groups   []struct {
				GroupName string `json:"group_name"`
			} `json:"groups"`
		} `json:"user"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, err
	}

	groups := make([]string, len(userResp.User.Groups))
	for i, group := range userResp.User.Groups {
		groups[i] = group.GroupName
	}

	return &User{
		UserName: userResp.User.UserName,
		Groups:   groups,
	}, nil
}
