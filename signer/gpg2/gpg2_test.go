package gpg2

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/mozilla-services/autograph/signer"
)

func assertNewSignerWithConfOK(t *testing.T, conf signer.Configuration) *GPG2Signer {
	s, err := New(gpg2signerconf)
	if s == nil {
		t.Fatal("expected non-nil signer for valid conf, but got nil signer")
	}
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	return s
}

func assertNewSignerWithConfErrs(t *testing.T, invalidConf signer.Configuration) {
	s, err := New(invalidConf)
	if s != nil {
		t.Fatalf("expected nil signer for invalid conf, but got non-nil signer %v", s)
	}
	if err == nil {
		t.Fatal("signer initialization did not fail")
	}
}

func TestNewSigner(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		_ = assertNewSignerWithConfOK(t, gpg2signerconf)
	})

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.Type = "badType"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid ID", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.ID = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.PrivateKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PublicKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.PublicKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid KeyID", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.KeyID = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("non-alphnumeric KeyID", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.KeyID = "!?;\\"
		assertNewSignerWithConfErrs(t, invalidConf)
	})
}

func TestConfig(t *testing.T) {
	t.Parallel()

	s := assertNewSignerWithConfOK(t, gpg2signerconf)

	if s.Config().Type != gpg2signerconf.Type {
		t.Fatalf("signer type %q does not match configuration %q", s.Config().Type, gpg2signerconf.Type)
	}
	if s.Config().ID != gpg2signerconf.ID {
		t.Fatalf("signer id %q does not match configuration %q", s.Config().ID, gpg2signerconf.ID)
	}
	if s.Config().PrivateKey != gpg2signerconf.PrivateKey {
		t.Fatalf("signer private key %q does not match configuration %q", s.Config().PrivateKey, gpg2signerconf.PrivateKey)
	}
}

func TestOptionsAreEmpty(t *testing.T) {
	t.Parallel()

	s := assertNewSignerWithConfOK(t, gpg2signerconf)
	defaultOpts := s.GetDefaultOptions()
	expectedOpts := Options{}
	if defaultOpts != expectedOpts {
		t.Fatalf("signer returned unexpected default options: %v", defaultOpts)
	}
}

func TestSignData(t *testing.T) {
	input := []byte("foobarbaz1234abcd")
	// initialize a signer
	s := assertNewSignerWithConfOK(t, gpg2signerconf)

	// sign input data
	sig, err := s.SignData(input, s.GetDefaultOptions())
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	// convert signature to string format
	sigstr, err := sig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal signature: %v", err)
	}

	t.Run("MarshalRoundTrip", func(t *testing.T) {
		t.Parallel()

		// convert string format back to signature
		sig2, err := Unmarshal(sigstr)
		if err != nil {
			t.Fatalf("failed to unmarshal signature: %v", err)
		}

		if !bytes.Equal(sig.(*Signature).Data, sig2.(*Signature).Data) {
			t.Fatalf("marshalling signature changed its format.\nexpected\t%q\nreceived\t%q",
				sig.(*Signature).Data, sig2.(*Signature).Data)
		}
	})

	t.Run("VerifyWithGnuPG", func(t *testing.T) {
		t.Parallel()

		// write the signature to a temp file
		tmpSignatureFile, err := ioutil.TempFile("", "gpg2_TestSignPGPAndVerifyWithGnuPG_signature")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpSignatureFile.Name())
		err = ioutil.WriteFile(tmpSignatureFile.Name(), []byte(sigstr), 0755)
		if err != nil {
			t.Fatalf("error writing file %s: %q", tmpSignatureFile.Name(), err)
		}

		// write the input to a temp file
		tmpContentFile, err := ioutil.TempFile("", "gpg2_TestSignPGPAndVerifyWithGnuPG_input")
		if err != nil {
			t.Fatal(err)
		}

		defer os.Remove(tmpContentFile.Name())
		err = ioutil.WriteFile(tmpContentFile.Name(), input, 0755)
		if err != nil {
			t.Fatal(err)
		}

		// write the public key to a temp file
		tmpPublicKeyFile, err := ioutil.TempFile("", "gpg2_TestSignPGPAndVerifyWithGnuPG_publickey")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpPublicKeyFile.Name())
		// fmt.Printf("loading %s\n", s.PublicKey)
		err = ioutil.WriteFile(tmpPublicKeyFile.Name(), []byte(s.PublicKey), 0755)
		if err != nil {
			t.Fatal(err)
		}

		defer os.Remove("/tmp/autograph_test_gpg2_keyring.gpg")
		defer os.Remove("/tmp/autograph_test_gpg2_secring.gpg")
		defer os.Remove("/tmp/autograph_test_gpg2_keyring.gpg~")

		// call gnupg to create a new keyring, load the key in it
		gnupgCreateKeyring := exec.Command("gpg", "--no-default-keyring",
			"--keyring", "/tmp/autograph_test_gpg2_keyring.gpg",
			"--secret-keyring", "/tmp/autograph_test_gpg2_secring.gpg",
			"--import", tmpPublicKeyFile.Name())
		out, err := gnupgCreateKeyring.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to load public key into keyring: %s\n%s", err, out)
		}

		// verify the signature
		gnupgVerifySig := exec.Command("gpg", "--no-default-keyring",
			"--keyring", "/tmp/autograph_test_gpg2_keyring.gpg",
			"--secret-keyring", "/tmp/autograph_test_gpg2_secring.gpg",
			"--verify", tmpSignatureFile.Name(), tmpContentFile.Name())
		out, err = gnupgVerifySig.CombinedOutput()
		if err != nil {
			t.Fatalf("error verifying sig: %s\n%s", err, out)
		}
		t.Logf("GnuPG PGP signature verification output:\n%s\n", out)
	})
}

var gpg2signerconf = signer.Configuration{
	ID:         "gpg2test",
	Type:       Type,
	KeyID:      "0xE09F6B4F9E6FDCCB",
	Passphrase: "abcdef123",
	PrivateKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQIVBFwaoDMBEAC0FVHFLTVYFSr8ZpCWOKyF+Xrpcr032pOr3p3rBH6Ld9ZTpaLS
5Vsx/u+utJ2Ci3vYde0DG07MS7RBky+rGgf4E1qwTCJb08s5mP0N6sg+J1Jmk03K
8jmXvnRO3208xMkbUdgIt7hbB7/2M85PwkQUaTsRdLM8WltDPl32fJS6HDk2jQsm
CR6u4yt4eZiRIo7k7G70j006kRRBvWgZO6v7DuF/umu1blLmKJdH8bP8WwPwUY0c
PRTVWYS3jFeqxqE95q5OFDsym8SkFUmZa0ftmSfqrvySRPC9HS09tkUHM2sIPPw2
thE+7RPrTRtiUIL1rkiEiyCWUSMoI1wfms5MrYV1uFqcEHdNmU9wEvfZz+IEGqM6
MhSjCJpXONOOefL9ovaMBoZrCm8W8LNvY8pYnwtYVcEeUq1aVS9JvWBzxzcijFSb
Pmzg/GhPbNOccreQpYA1Apk2PTfSmOYutSEUsDjj0mNwnMW7QTWrGidFwl8bRnKK
pPitNpLoLeWgikW9U6pHPX4Op5L2ptBq3PmWRoI7qPiYyaK5fv27aCVE7eWWODu/
dxubwZAfbsZzmE25+HAZkhDHGHbRVIw0Tklmq/VQw6UjNqxZ7zeiKbc0mddfgbyg
WnyNyROr/hlH3TOKU3S2TVUHoMevcxO2KvjzgCQ/9g1mtbs17vVMczrPIQARAQAB
/wBlAEdOVQG0PWF1dG9ncmFwaCB0ZXN0IHN1YmtleSA8YXV0b2dyYXBoX3Rlc3Rf
c3Via2V5X2dwZ0BleGFtcGxlLmNvbT6JAk4EEwEKADgWIQQdAtQsfCCGNz4rfY7Q
HvH6M8a66wUCXBqgMwIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRDQHvH6
M8a66zq+EACjMSBvOGEA0unr1hkaxLpyzVng/Ab2jd01NWlqCDnSzrcozBs8D/ss
3k31Z6VnSFlbeydKlOIKbYZjtVmlnhN1AV9loQ9xi3mWFVxvYdsBxuXdpp0fbRxt
1SdM0oxC/oOVQ/jyI4MDwJCyJk1AmTXJOp8QqM/uubW3wlz9u/ZxiZyp5mAE/z5C
Ab2/wQ0lFzllhc0PG0krPqSAUrHERSBAJIHBwcUrdomdjQs15kHz7ACcnn96bR1S
7d2wbdfLj2N0UfHcjspJHqqc4vQi4v4Uk0xe0h7nssuw/Z/yLpoILJJZaqGdTUdD
2/DyGuOrJnRdT3eh1nKa0W8yGNIny3K/anzouGb9mk1UKJH+vutHuKoFYT5W+JeB
dZQRDyssX8a1QiZnDTOAkg7uup+2AKV9fzpM9UirwMnjfmec6uhhySBU6LlpFPBL
gidSGGiIn3ztOpC+eFCcd7LUwjFZagQQCDeLaQeMkwTVcqSjATKOb3NGfT4i7G51
zdinh/T8fO3GQxS+2fNn08i1sJ3kMLrembV1sXwril8CxxhXclHXWkA7f9Lsm11A
x2FPwYQ8M8rL2qqkWS0LpSE3u0mOypU4yvPmxkC0PmmQVSWnDKPjPpb7uab2fGxc
Hed25IOF811+raxiLdFoEhgRNzEXcvzIMPKsOGHyGRHduB1PI9txhZ0HRgRcGqAz
ARAAp8e2XpVu7FdUx2kKW4R8FvAYRg4bPhSOYz+K/f0rv5cCRi1phGXBgdERkMnT
wzQ3JTk9avzi7UGSoXYqR1ObQaaHGIM0V1I47gxMj+ESNxLoRfXpG0/dmIu67znD
b7UqH2bzsQbowrPw3d3zwxz+cGyYxifyHrkWCZlkW22TklTVEpAGgNFPZNNtr4Q9
mYCbGmU9Iq3UGd9z28RFDZ4IquE0QcC18Jj8cyocR/AvCjY3JxHdoQMIXEaHY5AI
i4KGDN7A6ljOGA3yr5Y2jZdlp3cnlwx59k1kjquPVNrYhVqI7YMnWZsS1DMXcDNW
sW8GIzddo7j7V/am4rbIJt2DOyB+yfcX8nZTRNblnRymzwtNKHs4OWxO9pIzER7F
tljyOUNqMef1QzSHgguG+A6wue57L7cUQiSvlaqeIfNYJvLLTEXm4C94Y/aFiW29
GS93JGzf4Kw3hv6IfJTnf+k5/RDmjz/3p/7aAfc/bredx/3Zq19I5JeyHNV+tVNv
UHIQGYURkT1GjJr9hHlG4rSvyrqQ8dSGfhXG9I9adJkeDu4qp75hMsSnXHusjJ6b
9Z7RynWfe3ssv0U433/xPAgzUdtKDGiXIC2TMcd3icfncjWefdcZ14bfXRPo8Qa9
n493hc4jPQIdW83hokgqT2wseUYM6ryLLaLM+tDKGZkTQ+sAEQEAAf4HAwJqyW+J
EGJdgP/w+GswEGpuJosyaJLyGCWSg8z0KviTBNsKoDELVXiAQO6ewPkx7yiwn8Mn
w2LCFSbxOPi7K6yT50uvNhiVByCF+sRQjn8G8hT5lvt/nFxhEFKLmy1M+CoXt4gr
oRZRX5ohcRQRTo+uRQc8rbhyodgGU9geBZEX+jQ4fSI3hMe5AOQGK2VX+OhfnU6R
rUD7GRnbVm+E+EzEevSPl7feuBftA6PufAuoyngcqn3xPrx8gbpa0w34aiefme/+
YXB8SuDHt1YWmSMINdLxGK/bxWDk/+YuCtPc8CVd/EUFSKWJYg3iHuTB4D6lr/6d
Bh26I0THU2aYhUwKwtQq1SmQOA10L/DjTTlqJLN3M0pQ9KRSvn9EAX4icdkMpUHC
rrFxgbC6Qrz0+W5celmazFxrwvLpDP0yOpQlyaRU1fNh/VPiL0ZQcw6Q8p86z+ED
AJNst3OXVNp2WBQr/7Q8Gc1EOdnxU+8BwkoyQArn1h5S3fGyc1FBMR9SF+ISdnDc
Jftio1NgFUEumKspwZHIve4Q//1EVmE1XG8/tH2IZqzUyvQpcmvBx6q9fGasI5Om
9q3uNAolQ4vynIwYLd+dsbKUhJwYNjBggWDwh7NkkWuu+gW7zZ2Tv7uRo07Vwdhx
i2jHfbcv2Tjb0itX0TNAc/lr79oYmTWW5Zwdu1HuK63tPjRPWg6moCAHWRw1KumN
tVTO5YtfJNmM7nGSKlmmiybcShT6+r/mXFonnLQM84tbhcTu05AFATpT2s/HIbbC
9s5D/TNQqQF4Ta0x4AErkoSbGI/eyuPaiRINojHg5uA9jZbiWa9TmjHmgDdI0i3f
G7rjivkHt/4UOIZ1WUhQICVNVuccz86v+eoBNCVk9waBG3pLt4oyDfpvbJh43yd4
hhFaYcXYSwVRgLfdfzrfsWn8QvBcWb0209xikt8oTbCYlZkMOnJetuoMXTIPI2u8
hAkv7QTzHEcgbdPM50kPxnjaKuT3LRje5oMdsQjjUf7R0aEi0lV07XKJ5NoguiCg
HqSse2svSy5UrrqIoAFgOhaPXmJ4b+RO1SydBzvxJ9MyZ24FYb+M+xhEtrDuSNfC
RwY4+Uu3OC+GSSw6DRPyC7KkD06c4GIZGhF8ACb5m9Zhk8HCENUIpXp/Vv9cKZgP
PbxPsX2zsocJhX3BoOafWtvlUWMTv2ma1G5027HeD/yokp4LoHNskhMX3W4dQfpn
WHrhUqwZLejF2vOPfvHyrFCGIJ2LDVY/LVOkU3xd832i1uL6T2eBeVLcjcCrpW7b
hoUe4kegW+Vn5M7Z+6f9vPKrMSg2wxDdBeHHDxSNGIRy8COf60KfJPe44R6ibDlr
i0YWbWnS5t3JQqzwFAtCAsjozEnOCvz4c/YhX3uwmrVy25xmZI9xFYn6SVOUGqTx
keSTL3MREYFjoxuwwwWzKGSQT31Zu1W8BP2STKH8aGkhjydJduHYhI0AZlBnBAYy
4/39qwQpE9CRHaU73Q9pff49oGMVlftkcBkZC9+b3A1YOiZ004oess8xHUZLdDzt
jv1lUBeekoFOkXGyuqtn5svGEF+RxbblIIZqmZWrxUaUxPvfZZm1Bc6bBD3jcyoJ
AKkBeARObD6v2eT9qQojIR8g3ZvNmNSEpwYzRBL3fCTW9D79WNxsbeVA3bxobd3K
tTpm5hyFXellaxy7qUQzLVD2kKPK2MbahA8sbCi6Z7Dba4EjNQR51c4vcwh+4erb
sI1YkmwvIbG3bRgKYGztGJJKaFcGbX3sRUUJVuXmYw/miQI2BBgBCgAgFiEEHQLU
LHwghjc+K32O0B7x+jPGuusFAlwaoDMCGwwACgkQ0B7x+jPGuuthvg/9FTo07l1b
bXEsY1PLQjbvUY4v+kAvBUbhyCR1XQP2MvW3uyIQ3bMSN5aIzCtmNSeqSNa1GEK7
IJ6GlrkRniePS3lnRkTTbY0kfNhLZ8Q3JZZvVyipXmqm1amvtF+gKqvW2/F5ud7C
gFFpqJIKQld8kXCA5EROOPol6rZK0HmKm2vL6j5xI9GlNT0umjgyt580ALuocpgv
coaFE0AfRuLJ0I2Y9ne1Em3mBfSkFo78bZeh6xpuMkuIEmdJ9W/cPGRklH6pP5Nc
lDarQ8m8aXsKWwFsoouEmbr6bF2BGc/aA6JFINzgOoVopwqn+kuS5mjBgaNpV/Mw
yz1mJ9CEBCETpOpb8lu3By+wXWqaSlkFR+Gr46WQstV1Qxc0Wa8TqGLEVsvD1dHc
xWn394VQKfI6Lx0RwAHgfOIGt3N0bg61chPbeDjORfpl2efy4UaypnnP2Y8EXJZy
hTEFfzmX3lTAw2oQvX8qBv4Jh/0mIrALUOYGWW8Ev7/Cmj4Sv/SkwoW/iHRbB6Ye
sIpPWmjklu5xddzkh/6M54Gsa9xcC9echqjJduSGX6qxn8D2lZjJTO/wpAusJv+x
UeY/MZel76ZdUvgu5FDr4xlh5W4JVnITVZtKGPqejB8ynZcBPp0YrmyhhqXiOo1F
6V7ECHUcZAQy8KTkIr3cU0dyvJC+ShxOJ3OdB0YEXBqg2QEQAM+y9GHXKsbAYekp
IdtR7B9TdoXPZ2LStveScAgi6XIDOs9tiZJw1OPuc8EIUazVGMTa8JGU5Nkh6RFG
2TX2W7XV2yU78ZvGB2CXAl/sCTxKU5YDAbA3DOkFfL4Qb1MrIF3bzkQfC8pyx4FP
FTj6X0Hwp94Sy23MnKA2Ne3vXIHSz/Z52OVxsV13ny1Gxc4odJ+fyFsO1IHDSKD+
zjvggLH8K20Fx+D3r3jSZ9QAEeGLYxUs/npsJU4YFnOLiYQ6KV2VHW/dxtA4vgqT
bH5Pb7+HbU/0QlA+7hAMzFlr/zVQ3Vcny/3zG/xwRPYLaQgvF7Tp3NXUqINznjrB
F/8FonbFDcj+QiAJE3oG4vGAIledsY4nF7WKnZ44rA9PGAs4hLOs3torZglggnfN
bCUTBg5QnI7I/3jtCtSit1XPRE9tHXIOQB7SKXpBHL7Le+2/GaHzdyZoImh0H0Xx
mAuKL56tHjxESdA7Z7pVT0YWYG5Ip9+oKNgEp64BxgP74zXnKEJVIklthd3DD4ur
/V1v79VZHlVsZP/dYBkO8T3Q+f0VSgqgFi+l9HlWP75sJqIuvgcY9/DqcvfQ+M0G
Z2IEa+gtfxFJ7NAlLvEGWHIbfolqcTfY242x9AbJLi5ueSIHYt1aiCvEluHXbAnj
d/lgg3gs+Ii0nMg0PVVrL2XpRz69ABEBAAH+BwMCKyaace0uvJH/lp09pw4GbqrV
424cvfQrOs0y50RCS8o1Ju0BZmI/Sa6jwTH36xvW1Cc7k3u1ec05JH9ZgHktICgq
IaTDKNFnOSY456Euc03u9sb5tOMD64z7zZqZoNd937hzIjjUZWpd/5jzWG4C2mN+
KgAfIUKe7fiok0jHEMUJYJg/+9pIXi//lPN0qgApH/RdOrhRjcr2jA2FQWHqC8U+
BaA9PjGpYNv1oyDtRdJkYCH5rRtAzC60TXTHs9Ixf5FTLxy8ODjE1X7RJGtOcPw9
6NEMOvSw9I3OcGOHN9CgybXx0QDJ/YjsGqTRVmmSP3kImA4diudrLcWuevSF0VHr
1NOFHPi36ANzXWasBWIgVYlKrkqBJLkZ9wDp2oJf2wBul/x9AfU38SJYgS4HwQOy
npq5L+D0aIBuPVvJ7NDpZayO21bxfAa8Et35bT1roD0Sycfuat+qOZ+kmRoHroDN
X74fjbDn4WQZYGY4VQLBO2GJ1vrd9+zb2msP7EZZICcAg2A+UNeN6nnmnRoAS1Uz
I/1CTOnAtlMI4qzCKWGeXgn2YFx+nskb6dBJ3XXBvvtGKYJHyHafktdqBNSR3+CU
onZo/qIJu8mgq8/Rvo30IV6V1VpahcPWrxeNY9HlVRqBfhnIU2gWjBPLMhA4979G
Ehvg+3m4uX2cEYSjSp1nNPeErwm6Lyi7HGkvrWATuqh4Y5+xgUl4N7eFsuTh7ud+
uGAQ5mTWeBDDACeXuOY44Q91vcSQx9qmHz+ZCyiFlgZ5tkW3FH04lozS1B9EpY0w
uIEiJ+iBm9pSMfO9izoKzVvMG/Ci/l1G8pDk0Ub1oHNpEKqA2/bSCFD1RGe+/lYu
zp1bX9+4pjdtULzJ0SE1DG4Uyz+l+i8yAOkJ2bLp/vpSjQEDY0AAP1LVw0qnlTho
+nL0gzXPaKzMfjHFx7wohFvZPIf3aBPXGVARxKgwPX+8cvB2EoF7vUhUAG5ucvZX
ZPzxD4d/FTyyGm7MeN/PRKIPDfmNuptc2ryMcxWXXiREeEtnyc+JwfXWo6tOlWcG
u7aA+nTvT4BK6p593nQSsJj7mUAAVCipzppZRMgb4Ix6yCN/KTyeCw6V2FmS3max
IIaVPEZHC1shs9B9UAlhf3DN8CKHALAI2PyqDmmj/svQIRiHK2d3n+xkl56wtWO5
qO2M5BP7or9Szq5A1LXm5ckV7lNe0X/Bm6a5ewj5urhZb6z4hlYP4czHrQdcIFxL
Y2TqNKLdiXQWU5Ri244/td4tc5zY82FNIZtWDFAp/36jnGdor3u4Axrbi4oWbX5O
/KsyX5QO1Cwal0NhucCTHWJnhgs27QUgIKgqyDYhTMZrTNONU7FNBqLtemudXhjJ
3XcR3W0nkLpb7HebGSSaIkl0ovQ7YAW1dJiYdUXZOz0O5e7VU4SxMpkJf9E/dc5K
Ks+ylnTysmg6ePFmx5gCU5msihqvnRa9TSdxauualdqUsbascCcNJDcjWrZIsXTh
P6/2Hnk2+i0ZMCx2vhCGx/0uvBQjxOdcV9CcHPPnZ1Oq4tDtokE6FEClYtGqNODf
is3yI6L+z7rnKql6b5AcRaljfl3b6NmHeEsp+rGf1f5TVTT5izplKu84/Ko7/+BI
5DLtQthGAfyyvwh33agxuqJX0+KFE8CO3GggB+ma7AcHR9I96bt4x78PXi15lt2J
de7T9ZLRjIF9G2kd+3X1HSlk7ctroyUeK9miGJFVRFxb1g5mUrzsfArP469fnV4q
bXaXfIMJIlE+tQP3+GeCOQzD44kEbAQYAQoAIBYhBB0C1Cx8IIY3Pit9jtAe8foz
xrrrBQJcGqDZAhsCAkAJENAe8fozxrrrwXQgBBkBCgAdFiEEQw+hF5tfsLeq16ge
4J9rT55v3MsFAlwaoNkACgkQ4J9rT55v3Ms82Q//ZE1fAtJR8qCfFoqA53HECBvh
GRnMbZWAjfwUVt6zN6x/rVJEg3HKNgk/R18EVFNJsNXLyShEYsvoVVE8Rjd3IE3J
7jhlfvEObuEmMq2sOG8W0Uc5BC0wJ3gln2MRnhRXqwW6UqnCZ354l3eu09eU9q9q
d86oPu3eVJWgLHCJIYLr4jEYR5p1/CrTmpDs8dzCTUMPQl3VRPsuk6E8c5NbOkSb
+g45YeeWy+Yc8G4qCQJr6oa3SxGRFGbVTMf0Gem17u+BD3Of62bzP0ahv95atqWA
JGhxx6ql1vbvBU8suRSKGTvMfZ5KjPvX4gsk7Xp/p/pmjnW26/Wk6dJroRpgpU/A
m38IvvOYvU/GvhFTF0SVaKt2s8W+DSN5iDvC896wzPy2d+V5R2y0las/4bw3LsYR
jcEoNJGPgJglNCLlT0qb1VNEdrgi5BrhpYVW0Ez59U9wWYOKJZpt5/qTvvUyt+qD
ToMxyWTcY7sCiVKnFHwUfFm44M+8bbkREZjfhLzyR3K7eYnI4WCJVzbbC+Po0xAN
vj9P1l3izqjppkIQXBVVXlAGZZY7Xx0alG6DtzKy0XBeDkJCDOm1WKb5XmeJG+eL
wXkfrVWtkETDj7iKFnwZxvT2mll/SsYoH5r5olg1ZLaBAidNysyf8wrSAsV5LIY/
mBNg4rGj7jBZ22RFBEKjDBAAi6kjiSDnJYEWRfCkCuCiMl3mLh+F0J/UWI+1zE86
5d9X86nFPMUaxMvxWICU83FWWXqO7RVHj3eeX+UU7ngW7MTw4k2eDLN4IajSqyat
X+ALcPesa+LgSv5sAiOJLaj29kd43aP/yRvNzQW8aojXcoUDmeUCVwZvnOKxCqDx
keEW58m3rLaq9cDqFjGXs5E4HLz73+6gKkN2DI0KC7z69AT7ECwal/0g6VFGt8cy
Gjwx0RThXEbsdqMvNIr+Vqh1w9amkLMzWwqAXXK3+fycU/KKd43/UPiihs/hI+7L
Yjxbms1omGkKWE1ajf15fm1p41d6v6tTA495kx6yalPhjmV4YDwbJx+oIj2Jw8Lh
+B9lKvQvqaveUaTW7qFBWTDSuWkN20ArgcdgdqlIsmFWWUUNBuuwx9WJX7HVqYTf
UHHQdTuvCPy8q+1NPhPvbfJM8ryM+rp8rsVZg4roCgM+jIaULE/y+9W30ckHQOgA
bxhaHAQSZucbZqvyUSvLnVRT/0TKgm2NSDUOgrweyq5BqiFOE2god3OfyXzryWWs
W8amj8pJ+5MoBN6BRkcI1HnBXv4DvRPzn/qxiZLgAHgdeTn9pu+RLYJuOmYJJhR2
7YQ3SV4rdRRyiP7Ipobshhglh/xZWCcVXYQIXFF3vsKi2HTJvMo5MA+2gAAPg+05
bWI=
=J9W0
-----END PGP PRIVATE KEY BLOCK-----`,
	PublicKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
gAAPg+05bWI=
=459B
-----END PGP PUBLIC KEY BLOCK-----`,
}
