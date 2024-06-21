package apk2

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/mozilla-services/autograph/signer"
)

func assertNewSignerWithConfOK(t *testing.T, conf signer.Configuration) *APK2Signer {
	s, err := New(conf)
	if s == nil {
		t.Fatalf("%s: expected non-nil signer for valid conf, but got nil signer", t.Name())
	}
	if err != nil {
		t.Fatalf("%s: signer initialization failed with: %v", t.Name(), err)
	}
	return s
}

func assertNewSignerWithConfErrs(t *testing.T, invalidConf signer.Configuration) {
	s, err := New(invalidConf)
	if s != nil {
		t.Fatalf("%s: expected nil signer for invalid conf, but got non-nil signer\n%+v", t.Name(), invalidConf)
	}
	if err == nil {
		t.Fatalf("%s: signer initialization did not fail", t.Name())
	}
}

func TestNewSigner(t *testing.T) {
	t.Parallel()

	t.Run("valid no mode", func(t *testing.T) {
		t.Parallel()

		s := assertNewSignerWithConfOK(t, apk2signerconf)
		if s.v3Enabled {
			t.Fatalf("%s: unexpectedly enabled v3 signing", t.Name())
		}
	})

	t.Run("valid empty mode", func(t *testing.T) {
		t.Parallel()

		apk2signerconf.Mode = ""
		s := assertNewSignerWithConfOK(t, apk2signerconf)
		if s.v3Enabled {
			t.Fatalf("%s: unexpectedly enabled v3 signing", t.Name())
		}
	})

	t.Run("valid v3enabled mode", func(t *testing.T) {
		t.Parallel()

		s := assertNewSignerWithConfOK(t, apk2signerconfModeV3enabled)
		if !s.v3Enabled {
			t.Fatalf("%s: did not enable v3 signing", t.Name())
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()

		invalidConf := apk2signerconf
		invalidConf.Type = "badType"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid ID", func(t *testing.T) {
		t.Parallel()

		invalidConf := apk2signerconf
		invalidConf.ID = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid Mode", func(t *testing.T) {
		t.Parallel()

		invalidConf := apk2signerconf
		invalidConf.Mode = "invalidEnabled"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := apk2signerconf
		invalidConf.PrivateKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid Certificate", func(t *testing.T) {
		t.Parallel()

		invalidConf := apk2signerconf
		invalidConf.Certificate = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})
}

func TestConfig(t *testing.T) {
	t.Parallel()

	type fields struct {
		Configuration signer.Configuration
	}
	tests := []struct {
		name   string
		fields fields
		want   signer.Configuration
	}{
		{
			name: "config without mode",
			fields: fields{
				Configuration: apk2signerconf,
			},
			want: apk2signerconf,
		},
		{
			name: "config v3enabled mode",
			fields: fields{
				Configuration: apk2signerconfModeV3enabled,
			},
			want: apk2signerconfModeV3enabled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := assertNewSignerWithConfOK(t, tt.fields.Configuration)
			got := s.Config()

			if got.ID != tt.fields.Configuration.ID {
				t.Fatalf("signer id %q does not match configuration %q", got.ID, tt.fields.Configuration.ID)
			}
			if got.Type != tt.fields.Configuration.Type {
				t.Fatalf("signer type %q does not match configuration %q", got.Type, tt.fields.Configuration.Type)
			}
			if got.Mode != tt.fields.Configuration.Mode {
				t.Fatalf("signer mode %q does not match configuration %q", got.Mode, tt.fields.Configuration.Mode)
			}
			if got.PrivateKey != tt.fields.Configuration.PrivateKey {
				t.Fatalf("signer private key %q does not match configuration %q", got.PrivateKey, tt.fields.Configuration.PrivateKey)
			}
		})

	}
}

func TestOptionsAreEmpty(t *testing.T) {
	t.Parallel()

	s := assertNewSignerWithConfOK(t, apk2signerconf)
	defaultOpts := s.GetDefaultOptions()
	expectedOpts := Options{}
	if defaultOpts != expectedOpts {
		t.Fatalf("signer returned unexpected default options: %v", defaultOpts)
	}
}

func TestSignFile(t *testing.T) {
	// initialize a signer
	s := assertNewSignerWithConfOK(t, apk2signerconf)

	// sign input data
	signedFile, err := s.SignFile(testAPK, s.GetDefaultOptions())
	if err != nil {
		t.Fatalf("failed to sign file: %v", err)
	}

	t.Run("VerifyWithAPKSigner", func(t *testing.T) {
		t.Parallel()

		// write the signature to a temp file
		tmpApk, err := os.CreateTemp("", "apk2_TestSignedApkFile")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpApk.Name())
		err = os.WriteFile(tmpApk.Name(), signedFile, 0755)
		if err != nil {
			t.Fatalf("error writing file %s: %q", tmpApk.Name(), err)
		}

		// call apksigner to verify the APK
		apkSignerVerifySig := exec.Command("java", "-jar", "/usr/share/java/apksigner.jar", "verify", "--verbose", tmpApk.Name())
		out, err := apkSignerVerifySig.CombinedOutput()
		if err != nil {
			t.Fatalf("error verifying apk signature: %s\n%s", err, out)
		}
		t.Logf("APKSigner signature verification output:\n%s\n", out)
	})
}

func TestMarshalEmptySignature(t *testing.T) {
	t.Parallel()

	sig := Signature{
		Data:     []byte(""),
		Finished: true,
	}
	_, err := sig.Marshal()
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if err.Error() != "apk2: cannot marshal empty signature data" {
		t.Fatalf("expected to fail marshalling empty signature but got error '%v'", err)
	}
}

func TestUnmarshalBadSignatureBase64(t *testing.T) {
	t.Parallel()

	_, err := Unmarshal(`{{{{{`, []byte("foo"))
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if !strings.HasPrefix(err.Error(), "apk2.Unmarshal: failed to decode base64 signature") {
		t.Fatalf("expected to fail unmarshalling invalid base64 but got error '%v'", err)
	}
}

func TestUnmarshalBadSignaturePKCS7(t *testing.T) {
	t.Parallel()

	_, err := Unmarshal(`Y2FyaWJvdW1hdXJpY2UK`, []byte("foo"))
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if !strings.HasPrefix(err.Error(), "apk2.Unmarshal: failed to parse pkcs7 signature") {
		t.Fatalf("expected to fail parsing bad pkcs7 but got error '%v'", err)
	}
}

func TestVerifyUnfinishedSignature(t *testing.T) {
	t.Parallel()

	sig := Signature{
		Data:     []byte(""),
		Finished: false,
	}
	err := sig.Verify()
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if err.Error() != "apk2.Verify: cannot verify unfinished signature" {
		t.Fatalf("expected to fail verify unfinished signature but got error '%v'", err)
	}
}

var (
	apk2TestPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCAUrUDTS86CuqV
ctCo8jG8SSd4W/m/A4UF0J8T+la/pnJsZt2HhQ+Ma/+HmXF8QSeVax0LfrOaRmLy
OnfwOakP7QIGYtFsBQoLV5TWJzOr2ieonQS3h9xF865lNv+i9YPRGQT+ijjtKc49
mnb1vek+6/o8vfCMe7/5CE+fq2c/+yRjCJIstimDPfCTo5YHqXr2GaebQ006Vak2
sXhmp1sScGC/HYOuyris/AgmYHXGpNR4PLNWftoljp8m+PKwe8fy4zN83RqEEYnj
LzR0zOPad9Z4gD+89E/3tOsvxsRSjR2v6UTD+fVNeHs03fNsw8TeMcJfeMlKbO9a
72ZCZcdNAgMBAAECggEAN3iJOxYgdizF3zi0rnOTwFq3LzZDLakt1aerPI2Y9lvT
VrzYwn5ojEEbQti30AiyPcsB0ThCF0yZ9TAFLNkgFfxURcJt2Q4Mm36Onkxv77fs
MN0/br7SH4MJPkOaGi2bf8Ya/JVvqkXKG6MsDWq86zBDCgLpezD7eYF4OgN0LJmc
5aCmqipDWpmQ+EFRiQBrKIAalZLMPvdEFzD6U5jMch+gNiA09tUuJnI60sYvrbul
eJOwr8yv+CPSo8FA40Hwooy5Ab4kkkXxb3ypzVDas5QU7QVoaSrQYaQ6oKaCeKaH
YCKsPD3RIUilMHDhOOn4S/R5DlkYJNoXNHFq0hE3wQKBgQC+7KZVoalALOiZ5vNa
EUrWAUIGug2xIxtHIhGBz1oHjIOqowYaZSpa9jbFe0LbWiEveGn2j54MWUsQVtPy
MhHuI/1zsbFs29d44s1xP7tuggqcBGUwMMf5w36MavmnbTdxv5T29DNALz3xg/ax
IaiZiI4fswciDMXpFXfsL8SO+QKBgQCsD7LbMjbz9Mleia3QeyZ9sbV2EYFaps1X
RNntQqOow4itBXqMYBuKcoGoMR2eAMVT9ZDCtZaU00KJ608NI9yYb0xxPtNaqdlF
hqSn9C5khAwQmvDiV63QUTIMYqf2m3sCdwZaXSiYUXwjNXvyO63opZqgR9TwuZfO
h8B2DBZL9QKBgHAvhAl7JYWFHeQY9dNtp8iaEp77QkJcu5GPrjPVkDQxV8izZEms
OjgaxtJBfGaBzlAjdDgh6Z+d9GKUcpO04h5JXYtW1Ud+4lyxAEDUTyE/HlbQqlin
wUm8mqaN0UaVAWhAR5rYoSjM2ZwJi7JHcddNix2LR9y1HrG4ILBS3S+ZAoGAfVme
gsRtdoNSJNaG04i0fQP3YEHWjDVTCY32ejx/QJbbPrnsEtJ9nfpX7TGDEzYajFUt
ljx2rIvQQOw2FiuXLVKATUxo6/cre9Rgpp9lIQN2Sq6maS9ZSJeur4k8NpQFJMGT
1kdiKL3Mg1YWq13BD+l94eETCCEdsHADzbx2jfUCgYAjJk016W+hugkU7rtAHIaP
Q9+gIrgtjJrWCw6SHF3pIB749A1J4NMlQ+0XjPhcwSMrxxkMTwmLhgSEHZcVl3C6
zw097oFSo1ZF/8Qpe3cb3252I9MOWKSXWTJ1BP2iVlCp0jRteFCJj8SB2CAnay9F
1KDtwVd+U8cK/z6UQxo8YQ==
-----END PRIVATE KEY-----`
	apk2TestCert = `-----BEGIN CERTIFICATE-----
MIIDyTCCArGgAwIBAgIEVxuKpDANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xHDAaBgNVBAsTE1JlbGVhc2Ug
RW5naW5lZXJpbmcxHDAaBgNVBAMTE1JlbGVhc2UgRW5naW5lZXJpbmcwHhcNMTgw
MTE5MTgwNzMyWhcNNDUwNjA2MTgwNzMyWjCBlDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxHDAaBgNVBAoT
E01vemlsbGEgQ29ycG9yYXRpb24xHDAaBgNVBAsTE1JlbGVhc2UgRW5naW5lZXJp
bmcxHDAaBgNVBAMTE1JlbGVhc2UgRW5naW5lZXJpbmcwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCAUrUDTS86CuqVctCo8jG8SSd4W/m/A4UF0J8T+la/
pnJsZt2HhQ+Ma/+HmXF8QSeVax0LfrOaRmLyOnfwOakP7QIGYtFsBQoLV5TWJzOr
2ieonQS3h9xF865lNv+i9YPRGQT+ijjtKc49mnb1vek+6/o8vfCMe7/5CE+fq2c/
+yRjCJIstimDPfCTo5YHqXr2GaebQ006Vak2sXhmp1sScGC/HYOuyris/AgmYHXG
pNR4PLNWftoljp8m+PKwe8fy4zN83RqEEYnjLzR0zOPad9Z4gD+89E/3tOsvxsRS
jR2v6UTD+fVNeHs03fNsw8TeMcJfeMlKbO9a72ZCZcdNAgMBAAGjITAfMB0GA1Ud
DgQWBBTpkU1g44JTIoVS0ARI3och7+50DzANBgkqhkiG9w0BAQsFAAOCAQEAUGDm
suWrrN6ireyvv+SoVYZHP6YxfcNlOos41wPG2548gL0OirAjdc7+3FRl2WAuseY5
79RknrC1yTUUxRtoiNBAMp9NQ7jHiQLheaiZuMhf2IVXfgJf9qxfHy+6Z/tPfOt9
4pkbJiIlZWJbFM6FgnhEBgwJygtO0mAa5FT7UckF0TnRJfjpZKJ7YETflITyiZ7f
i+UaOY4AHXEAn1t3FuRW4J2W4tku4XmAZys9ATX0/LVbm/R3pqGYmTAqv0SDnStM
Gg/He+3S+8Rq0zqXAbOVJDVSTCRV5C9ZOmTWedBzaqmykScsCxLSpmEffy2RrtBU
dNKAPtSx4o34NaTpxg==
-----END CERTIFICATE-----`
	apk2signerconf = signer.Configuration{
		ID:          "apk2test",
		Type:        Type,
		PrivateKey:  apk2TestPrivateKeyPEM,
		Certificate: apk2TestCert,
	}
	apk2signerconfModeV3enabled = signer.Configuration{
		ID:          "apk2testv3enabled",
		Type:        Type,
		Mode:        "v3enabled",
		PrivateKey:  apk2TestPrivateKeyPEM,
		Certificate: apk2TestCert,
	}
)
