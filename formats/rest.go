package formats

// SigningFile is a file to sign when included in a request to sign
// multiple files or a signed file when included in a response to
// signing multiple files
type SigningFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// SignatureRequest is sent by a client to request a signature on input data
type SignatureRequest struct {
	Input   string        `json:"input"`
	Files   []SigningFile `json:"files,omitempty"`
	KeyID   string        `json:"keyid,omitempty"`
	Options interface{}
}

// SignatureResponse is returned by autograph to a client with
// a signature computed on input data
type SignatureResponse struct {
	Ref         string        `json:"ref"`
	Type        string        `json:"type"`
	Mode        string        `json:"mode"`
	SignerID    string        `json:"signer_id"`
	PublicKey   string        `json:"public_key"`
	Signature   string        `json:"signature,omitempty"`
	SignedFile  string        `json:"signed_file,omitempty"`
	SignedFiles []SigningFile `json:"signed_files,omitempty"`
	X5U         string        `json:"x5u,omitempty"`
	SignerOpts  interface{}   `json:"signer_opts,omitempty"`
}
