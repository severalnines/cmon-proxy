package api

type PingRequest struct {
	*WithOperation       `json:",inline"`
	*WithClusterIDForced `json:",inline"`
}

type PingResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Name    string `json:"package_name"`
	Version string `json:"package_version"`
}
