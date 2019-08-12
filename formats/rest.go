package formats

// SignatureRequest is sent by a client to request a signature on input data
type SignatureRequest struct {
	Input   string `json:"input"`
	KeyID   string `json:"keyid,omitempty"`
	Options interface{}
}

// SignatureResponse is returned by autograph to a client with
// a signature computed on input data
type SignatureResponse struct {
	Ref        string      `json:"ref"`
	Type       string      `json:"type"`
	Mode       string      `json:"mode"`
	SignerID   string      `json:"signer_id"`
	PublicKey  string      `json:"public_key"`
	Signature  string      `json:"signature,omitempty"`
	SignedFile string      `json:"signed_file,omitempty"`
	X5U        string      `json:"x5u,omitempty"`
	SignerOpts interface{} `json:"signer_opts,omitempty"`
}
