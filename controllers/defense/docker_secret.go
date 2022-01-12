package defense

import (
	"encoding/base64"
	"encoding/json"

	defensev1 "scm.tensorsecurity.cn/tensorsecurity-rd/tensor-operator/apis/defense/v1"
)

type DockerConfigJSON struct {
	Auths DockerConfig `json:"auths" datapolicy:"token"`
	// +optional
	HttpHeaders map[string]string `json:"HttpHeaders,omitempty" datapolicy:"token"`
}

type DockerConfig map[string]DockerConfigEntry

// DockerConfigEntry holds the user information that grant the access to docker registry
type DockerConfigEntry struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty" datapolicy:"password"`
	Email    string `json:"email,omitempty"`
	Auth     string `json:"auth,omitempty" datapolicy:"token"`
}

// func dockerCfgJSONContent(username, password, email, server string) ([]byte, error) {
// 	dockerConfigAuth := DockerConfigEntry{
// 		Username: username,
// 		Password: password,
// 		Email:    email,
// 		Auth:     encodeDockerConfigFieldAuth(username, password),
// 	}
// 	dockerConfigJSON := DockerConfigJSON{
// 		Auths: map[string]DockerConfigEntry{server: dockerConfigAuth},
// 	}

// 	return json.Marshal(dockerConfigJSON)
// }

func dockerCfgJSONContent(secrets []defensev1.ImagePullSecret) ([]byte, error) {
	dockerConfigJSON := DockerConfigJSON{
		Auths: make(map[string]DockerConfigEntry),
	}

	for _, s := range secrets {
		dockerConfigAuth := DockerConfigEntry{
			Username: s.UserName,
			Password: s.Password,
			Email:    s.Email,
			Auth:     encodeDockerConfigFieldAuth(s.UserName, s.Password),
		}
		dockerConfigJSON.Auths[s.Server] = dockerConfigAuth
	}

	return json.Marshal(dockerConfigJSON)
}

// encodeDockerConfigFieldAuth returns base64 encoding of the username and password string
func encodeDockerConfigFieldAuth(username, password string) string {
	fieldValue := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(fieldValue))
}
