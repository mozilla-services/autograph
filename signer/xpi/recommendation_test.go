package xpi

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/mozilla-services/autograph/signer"
)

func TestValidateRecommendation(t *testing.T) {
	t.Parallel()

	twoYears, err := time.ParseDuration("17532h")
	if err != nil {
		t.Fatalf("failed to parse duration for test fixture: %q", err)
	}
	allowedRecommendationStates := map[string]bool{
		"recommended": true,
	}
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("Validate checks a valid Recommendation", func(t *testing.T) {
		t.Parallel()

		rec := Recommend("example@mozilla", []string{"recommended"}, now, now.Add(twoYears))
		err := rec.Validate(allowedRecommendationStates)
		if err != nil {
			t.Fatalf("rec %+v did not validate as expected got err %q", rec, err)
		}
	})

	// assert addonID matches email format?
	t.Run("Validate checks addon_id in recommendation", func(t *testing.T) {
		t.Parallel()

		state := []string{"recommended"}
		rec := Recommend("example@mozilla", state, now, now.Add(twoYears))
		rec.States = []string{}
		err := rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v missing state validated when it should not have at least one", rec)
		}
	})

	t.Run("Validate checks at least one state in recommendation", func(t *testing.T) {
		t.Parallel()

		state := []string{"recommended"}
		rec := Recommend("example@mozilla", state, now, now.Add(twoYears))
		rec.States = []string{}
		err := rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v missing state validated when it should not have at least one", rec)
		}
	})

	t.Run("Validate checks states are whitelisted", func(t *testing.T) {
		t.Parallel()

		state := []string{"not-recommended"}
		rec := Recommend("example@mozilla", state, now, now.Add(twoYears))
		rec.States = []string{
			"recommended",
			state[0],
		}
		err := rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid state %q validated when it should not have", rec, state)
		}
	})

	t.Run("Validate checks validity only includes not_before and not_after fields", func(t *testing.T) {
		t.Parallel()

		rec := Recommend("example@mozilla", []string{"recommended"}, now, now.Add(twoYears))
		rec.Validity["foo"] = now
		err := rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid validity with extra field validated when it should not have", rec)
		}

		rec.Validity = map[string]time.Time{}
		err = rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid with empty validity validated when it should not have", rec)
		}

		rec.Validity = map[string]time.Time{
			"not_before": now,
			"other_key":  now,
		}
		err = rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid with missing not_after validated when it should not have", rec)
		}

		rec.Validity = map[string]time.Time{
			"not_after": now,
			"other_key": now,
		}
		err = rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid with missing not_before validated when it should not have", rec)
		}

	})

	t.Run("Validate checks validity not_before is before not_after", func(t *testing.T) {
		t.Parallel()

		rec := Recommend("example@mozilla", []string{"recommended"}, now.Add(twoYears), now)
		err := rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid validity (not_before after not_after) validated when it should not have", rec)
		}
	})

	t.Run("Validate checks validity ts are UTC", func(t *testing.T) {
		t.Parallel()

		nonUTCnow := time.Now().Truncate(time.Second)

		rec := Recommend("example@mozilla", []string{"recommended"}, nonUTCnow, now.Add(twoYears))
		err := rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid validity (not_before not UTC ts) validated when it should not have", rec)
		}

		rec = Recommend("example@mozilla", []string{"recommended"}, now, nonUTCnow.Add(twoYears))
		err = rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid validity (not_after not UTC ts) validated when it should not have", rec)
		}
	})

	t.Run("Validate checks validity ts drop nanoseconds", func(t *testing.T) {
		t.Parallel()

		nowWithNanos := time.Now().UTC()

		rec := Recommend("example@mozilla", []string{"recommended"}, nowWithNanos, now.Add(twoYears))
		err := rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid validity (not_before includes nanos) validated when it should not have", rec)
		}

		rec = Recommend("example@mozilla", []string{"recommended"}, now, nowWithNanos.Add(twoYears))
		err = rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid validity (not_after includes nanos) validated when it should not have", rec)
		}
	})

	t.Run("Validate checks schema_version is 1", func(t *testing.T) {
		t.Parallel()

		rec := Recommend("example@mozilla", []string{"recommended"}, now, now.Add(twoYears))
		rec.SchemaVersion = -3
		err := rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid schema version validated when it should not have", rec)
		}
		rec.SchemaVersion = 2
		err = rec.Validate(allowedRecommendationStates)
		if err == nil {
			t.Fatalf("rec %+v with invalid schema version validated when it should not have", rec)
		}
	})

}

func TestMakeRecommendationFile(t *testing.T) {
	t.Parallel()

	var recTestCase signer.Configuration
	for _, testcase := range PASSINGTESTCASES {
		if testcase.Mode == ModeAddOnWithRecommendation {
			recTestCase = testcase
			break
		}
	}

	t.Run("makes a recommendation file", func(t *testing.T) {
		t.Parallel()

		// initialize a signer
		s, err := New(recTestCase, nil)
		if err != nil {
			t.Fatalf("testcase signer initialization failed with: %v", err)
		}

		opts := s.GetDefaultOptions().(Options)
		opts.Recommendations = []string{"recommended"}

		recFileBytes, err := s.makeRecommendationFile(opts, "example@mozilla")
		if err != nil {
			t.Fatalf("failed to make recommendation file as expected got err: %q", err)
		}
		fmt.Printf("%q\n", recFileBytes)
		rec, err := UnmarshalRecommendation(recFileBytes)
		if err != nil {
			t.Fatalf("failed to unmarshal recommendation file back to rec got err: %q", err)
		}
		err = rec.Validate(s.recommendationAllowedStates)
		if err != nil {
			t.Fatalf("unmarshaled recommendation file was invalid with err: %q", err)
		}
		if rec.AddOnID != "example@mozilla" {
			t.Fatalf("unmarshaled recommendation file used unexpected addonid: %q (expected example@mozilla)", rec.AddOnID)
		}
		if len(rec.States) != 1 && rec.States[0] != "recommended" {
			t.Fatalf("unmarshaled recommendation file contains unexpected states: %q (expected [\"recommended\"])", rec.States)
		}
	})

	t.Run("fails for signer not in rec mode", func(t *testing.T) {
		t.Parallel()

		// initialize a signer
		s, err := New(PASSINGTESTCASES[0], nil)
		if err != nil {
			t.Fatalf("testcase %d signer initialization failed with: %v", 0, err)
		}

		opts := s.GetDefaultOptions().(Options)

		_, err = s.makeRecommendationFile(opts, "example@mozilla")
		if err == nil {
			t.Fatalf("did not fail to make recommendation file for non-rec signer")
		}
	})

	t.Run("fails for invalid options", func(t *testing.T) {
		t.Parallel()

		// hack to deep copy the configuration so we don't change allowed state by ref breaking other tests
		var dupRecTestCase signer.Configuration
		buf, err := json.Marshal(recTestCase)
		if err != nil {
			t.Fatalf("failed to marshal testcase for signer %q", err)
		}
		err = json.Unmarshal(buf, &dupRecTestCase)
		if err != nil {
			t.Fatalf("failed to unmarshal testcase for signer %q", err)
		}

		// initialize a signer
		s, err := New(dupRecTestCase, nil)
		if err != nil {
			t.Fatalf("testcase signer initialization failed with: %v", err)
		}

		opts := s.GetDefaultOptions().(Options)
		opts.Recommendations = []string{"recommended"}

		s.recommendationAllowedStates["recommended"] = false
		_, err = s.makeRecommendationFile(opts, "example@mozilla")
		if err == nil {
			t.Fatalf("did not fail to make recommendation file for signer with invalid rec state options with expected error")
		} else if err.Error() != "xpi: error parsing recommendations from options: xpi: invalid or unsupported recommendation state \"recommended\"" {
			t.Fatalf("did not fail to make recommendation file for signer with invalid rec state options with expected error. got %q", err)
		}

		// reset state the other subtests depend on so they pass
		s.recommendationAllowedStates["recommended"] = true
	})

	t.Run("fails for invalid recommendation validity not_before after not_after", func(t *testing.T) {
		t.Parallel()

		// initialize a signer
		s, err := New(recTestCase, nil)
		if err != nil {
			t.Fatalf("testcase signer initialization failed with: %v", err)
		}
		duration, err := time.ParseDuration("-32839h")
		if err != nil {
			t.Fatalf("failed to parse duration for test fixture: %v", err)
		}
		s.recommendationValidityRelativeStart = duration
		s.recommendationValidityDuration = duration

		opts := s.GetDefaultOptions().(Options)
		opts.Recommendations = []string{"recommended"}

		_, err = s.makeRecommendationFile(opts, "example@mozilla")
		if err == nil {
			t.Fatalf("did not fail to make recommendation file for signer with invalid rec state options with expected error")
		} else if err.Error() != "xpi: recommendation validation failed: xpi: recommendation validity not_after must be after not_before field" {
			t.Fatalf("did not fail to make recommendation file for signer with validation failing with expected error. got %q", err)
		}
	})
}

func TestRecommendationMarshalsAndUnmarshalsToJSON(t *testing.T) {
	t.Parallel()

	twoYears, err := time.ParseDuration("17532h")
	if err != nil {
		t.Fatalf("failed to parse duration for test fixture: %q", err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("marshals and unmarshals", func(t *testing.T) {
		rec := Recommend("example@mozilla", []string{"recommended"}, now, now.Add(twoYears))
		recFileBytes, err := rec.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal recommendation. Got err: %q", err)
		}

		rec, err = UnmarshalRecommendation(recFileBytes)
		if err != nil {
			t.Fatalf("failed to unmarshal recommendation file back to rec. Got err: %q", err)
		}
	})

	t.Run("errs for invalid JSON but not invalid recs", func(t *testing.T) {
		t.Parallel()

		_, err := UnmarshalRecommendation([]byte(""))
		if err == nil {
			t.Fatalf("failed to err unmarshaling empty recommendation file")
		}

		_, err = UnmarshalRecommendation([]byte(`{addon_id":"example@mozilla","states":["recommended"],"validity":{"not_after":"2019-08-13T17:05:14Z","not_before":"2019-05-29T16:05:14Z"},"schema_version":2}`))
		if err == nil {
			t.Fatalf("failed to err unmarshaling invalid JSON recommendation file")
		}
	})
}

func TestRecommendationNotIncludedInOtherSignerModes(t *testing.T) {
	t.Parallel()

	input := unsignedWithRec

	for i, testcase := range PASSINGTESTCASES {
		// skip signers that support recommendations
		if testcase.Mode == ModeAddOnWithRecommendation {
			continue
		}

		tc := testcase // capture range variable
		tcName := fmt.Sprintf("%d %q", i, testcase.ID)

		t.Run(tcName, func(t *testing.T) {
			t.Parallel()

			// initialize a signer
			s, err := New(tc, nil)
			if err != nil {
				t.Fatalf("testcase %d signer initialization failed with: %v", i, err)
			}
			// tell it about the recommendations file
			s.recommendationFilePath = "test-recommendations.json"

			// try to sign an input file that already has a recommendations file
			signOptions := Options{
				ID:          "test@example.net",
				PKCS7Digest: "SHA1",
			}
			signedXPI, err := s.SignFile(input, signOptions)
			_, err = readFileFromZIP(signedXPI, s.recommendationFilePath)
			if err == nil {
				t.Fatalf("signer %q in mode %q did not remove recommendations file at %q", tc.ID, tc.Mode, s.recommendationFilePath)
			}
		})
	}
}

func TestSignFileWithRecommendation(t *testing.T) {
	t.Parallel()

	var recTestCase signer.Configuration
	for _, testcase := range PASSINGTESTCASES {
		if testcase.Mode == ModeAddOnWithRecommendation {
			recTestCase = testcase
			break
		}
	}

	t.Run("signs unsignedbootstrap with PK7", func(t *testing.T) {
		input := unsignedBootstrap

		s, err := New(recTestCase, nil)
		if err != nil {
			t.Fatalf("signer initialization failed with: %v", err)
		}

		opts := s.GetDefaultOptions().(Options)
		opts.Recommendations = []string{"recommended"}

		signedXPI, err := s.SignFile(input, opts)
		if err != nil {
			t.Fatalf("failed to sign file with rec: %v", err)
		}
		err = VerifySignedFile(signedXPI, nil, opts, time.Now().UTC())
		if err != nil {
			t.Fatalf("failed to verify signed file with rec: %v", err)
		}
		_, err = s.ReadAndVerifyRecommendationFile(signedXPI)
		if err != nil {
			t.Fatalf("failed to verify signed rec file: %v", err)
		}
	})

	t.Run("signs unsignedbootstrap with PK7 and COSE", func(t *testing.T) {
		input := unsignedBootstrap

		// verify against the issuer/intermediate
		truststore := x509.NewCertPool()
		ok := truststore.AppendCertsFromPEM([]byte(recTestCase.Certificate))
		if !ok {
			t.Fatalf("failed to add issuer cert to pool")
		}

		s, err := New(recTestCase, nil)
		if err != nil {
			t.Fatalf("signer initialization failed with: %v", err)
		}

		opts := s.GetDefaultOptions().(Options)
		opts.COSEAlgorithms = []string{"ES256"}
		opts.Recommendations = []string{"recommended"}

		signedXPI, err := s.SignFile(input, opts)
		if err != nil {
			t.Fatalf("failed to sign file with rec: %v", err)
		}
		err = VerifySignedFile(signedXPI, truststore, opts, time.Now().UTC())
		if err != nil {
			t.Fatalf("failed to verify signed file with rec: %v", err)
		}
		_, err = s.ReadAndVerifyRecommendationFile(signedXPI)
		if err != nil {
			t.Fatalf("failed to verify signed rec file: %v", err)
		}
	})

	t.Run("signs unsignedbootstrap with PK7 fails for disallowed rec. state", func(t *testing.T) {
		input := unsignedBootstrap

		s, err := New(recTestCase, nil)
		if err != nil {
			t.Fatalf("signer initialization failed with: %v", err)
		}

		opts := s.GetDefaultOptions().(Options)
		opts.Recommendations = []string{"not-recommended"}

		_, err = s.SignFile(input, opts)
		if err == nil {
			t.Fatalf("did not fail to sign file with bad  rec state")
		}
	})

	t.Run("signs unsigned with rec PK7 and overwrites existing rec file", func(t *testing.T) {
		input := unsignedBootstrap

		s, err := New(recTestCase, nil)
		if err != nil {
			t.Fatalf("signer initialization failed with: %v", err)
		}

		opts := s.GetDefaultOptions().(Options)
		opts.Recommendations = []string{"standard"}

		signedXPI, err := s.SignFile(input, opts)
		if err != nil {
			t.Fatalf("failed to sign file with rec: %v", err)
		}
		err = VerifySignedFile(signedXPI, nil, opts, time.Now().UTC())
		if err != nil {
			t.Fatalf("failed to verify signed file with rec: %v", err)
		}
		recFileBytes, err := s.ReadAndVerifyRecommendationFile(signedXPI)
		if err != nil {
			t.Fatalf("failed to verify signed rec file: %v", err)
		}
		rec, err := UnmarshalRecommendation(recFileBytes)
		if err != nil {
			t.Fatalf("failed to unmarshal invalid JSON recommendation file %q", err)
		}
		if string(rec.AddOnID) != opts.ID {
			t.Fatalf("failed to use new CN in recommendation file expected %q and got %q", opts.ID, string(rec.AddOnID))
		}
		// fmt.Printf("%s\n", recFileBytes)
	})
}

// fetched from https://searchfox.org/mozilla-central/source/toolkit/mozapps/extensions/test/xpcshell/data/signing_checks/unsigned.xpi
// added an a rec file and converted with:
//
// hexdump -v -e '16/1 "_x%02X" "\n"' /tmp/fakeapk/fakeapk.zip | sed 's/_/\\/g; s/\\x  //g; s/.*/    "&"/'
//
// » zipinfo unsigned-wd/unsigned-with-rec.xpi
// Archive:  unsigned-wd/unsigned-with-rec.xpi
// Zip file size: 797 bytes, number of entries: 3
// -rw-r--r--  3.0 unx      153 tx defN 18-Nov-20 15:41 manifest.json
// -rw-rw-r--  3.0 unx      162 tx defN 19-May-29 14:10 test-recommendations.json
// -rw-r--r--  3.0 unx       55 tx stor 18-Nov-09 20:05 test.txt
// 3 files, 370 bytes uncompressed, 299 bytes compressed:  19.2%
// » cat unsigned-wd/test-recommendations.json
// {"addon_id":"test@somewhere.com","states":["recommended"],"validity":{"not_after":"2019-08-13T19:08:26Z","not_before":"2019-05-29T18:08:26Z"},"schema_version":1}
var unsignedWithRec = []byte(
	"\x50\x4B\x03\x04\x14\x00\x00\x00\x08\x00\x24\x7D\x74\x4D\x72\x3F" +
		"\x91\xD5\x70\x00\x00\x00\x99\x00\x00\x00\x0D\x00\x1C\x00\x6D\x61" +
		"\x6E\x69\x66\x65\x73\x74\x2E\x6A\x73\x6F\x6E\x55\x54\x09\x00\x03" +
		"\x63\x71\xF4\x5B\x7B\xC9\xEE\x5C\x75\x78\x0B\x00\x01\x04\xE8\x03" +
		"\x00\x00\x04\xE8\x03\x00\x00\x45\x8C\xB1\x0E\x84\x20\x10\x44\x7B" +
		"\xBE\x82\x6C\x7D\x1A\x63\x79\xD5\xF9\x0F\xF6\x86\xC0\xEA\x11\x05" +
		"\x8C\x10\x2D\x88\xFF\xEE\x60\xA1\xC5\x16\xF3\xDE\xCC\x66\x21\x25" +
		"\x39\xE5\xED\xC8\x31\x0D\x3B\x6F\xD1\x06\x4F\x5F\xD9\x7E\x8A\xF0" +
		"\xCA\x31\x02\xF5\x90\xB2\x33\xA6\x82\xBB\xC5\x5B\xA4\xB6\x6E\xC0" +
		"\x0A\x54\xEB\xBA\x58\xAD\x12\x44\x84\xC9\x60\xA0\x13\xEB\x39\x3C" +
		"\x11\xC0\x9A\x32\x4B\x78\xF9\x8B\xC1\xF1\xF1\xE7\x8D\x6B\x1D\x1C" +
		"\xDD\x85\x53\x94\x3B\xC5\x05\x50\x4B\x03\x04\x14\x00\x00\x00\x08" +
		"\x00\x57\x71\xBD\x4E\x3D\xBF\x2C\x77\x84\x00\x00\x00\xA2\x00\x00" +
		"\x00\x19\x00\x1C\x00\x74\x65\x73\x74\x2D\x72\x65\x63\x6F\x6D\x6D" +
		"\x65\x6E\x64\x61\x74\x69\x6F\x6E\x73\x2E\x6A\x73\x6F\x6E\x55\x54" +
		"\x09\x00\x03\x25\xCB\xEE\x5C\x25\xCB\xEE\x5C\x75\x78\x0B\x00\x01" +
		"\x04\xE8\x03\x00\x00\x04\xE8\x03\x00\x00\x3D\x8D\x41\x0A\xC2\x30" +
		"\x10\x00\xEF\x3E\x63\xCF\xAD\x24\x11\x25\xD9\x93\x8F\xE8\xA9\x22" +
		"\x21\x76\xB7\x34\x60\x12\x48\x42\x45\x4A\xFF\x6E\x3C\xE8\x75\x18" +
		"\x66\x36\x70\x44\x29\x5A\x4F\x80\x50\xB9\xD4\x6B\x49\x81\x5F\x0B" +
		"\x67\x3E\x4E\x29\x40\x07\xA5\xBA\xC6\x01\x6F\x90\xB9\x91\xC0\x91" +
		"\x98\xE0\xDE\xC1\xEA\x9E\x9E\x7C\x7D\x03\x6E\x10\x53\xB5\x6E\xAE" +
		"\x9C\x5B\x45\x09\x69\x7A\xA1\x7B\x79\x1A\xA4\x41\xA1\x51\x5D\xC6" +
		"\xD6\xF9\x2A\x0F\x9E\x53\xE6\xBF\x73\xEE\x95\x19\xA4\xFE\x39\x7B" +
		"\x9B\x4D\x0B\x07\x67\x57\xCE\xC5\xA7\x08\x28\xF7\xC3\x07\x50\x4B" +
		"\x03\x04\x0A\x00\x00\x00\x00\x00\xA7\xA0\x69\x4D\x7D\xB5\xAF\x6B" +
		"\x37\x00\x00\x00\x37\x00\x00\x00\x08\x00\x1C\x00\x74\x65\x73\x74" +
		"\x2E\x74\x78\x74\x55\x54\x09\x00\x03\xCA\x2E\xE6\x5B\x87\xC9\xEE" +
		"\x5C\x75\x78\x0B\x00\x01\x04\xE8\x03\x00\x00\x04\xE8\x03\x00\x00" +
		"\x54\x68\x69\x73\x20\x74\x65\x73\x74\x20\x66\x69\x6C\x65\x20\x63" +
		"\x61\x6E\x20\x62\x65\x20\x61\x6C\x74\x65\x72\x65\x64\x20\x74\x6F" +
		"\x20\x62\x72\x65\x61\x6B\x20\x73\x69\x67\x6E\x69\x6E\x67\x20\x63" +
		"\x68\x65\x63\x6B\x73\x2E\x0A\x50\x4B\x01\x02\x1E\x03\x14\x00\x00" +
		"\x00\x08\x00\x24\x7D\x74\x4D\x72\x3F\x91\xD5\x70\x00\x00\x00\x99" +
		"\x00\x00\x00\x0D\x00\x18\x00\x00\x00\x00\x00\x01\x00\x00\x00\xA4" +
		"\x81\x00\x00\x00\x00\x6D\x61\x6E\x69\x66\x65\x73\x74\x2E\x6A\x73" +
		"\x6F\x6E\x55\x54\x05\x00\x03\x63\x71\xF4\x5B\x75\x78\x0B\x00\x01" +
		"\x04\xE8\x03\x00\x00\x04\xE8\x03\x00\x00\x50\x4B\x01\x02\x1E\x03" +
		"\x14\x00\x00\x00\x08\x00\x57\x71\xBD\x4E\x3D\xBF\x2C\x77\x84\x00" +
		"\x00\x00\xA2\x00\x00\x00\x19\x00\x18\x00\x00\x00\x00\x00\x01\x00" +
		"\x00\x00\xB4\x81\xB7\x00\x00\x00\x74\x65\x73\x74\x2D\x72\x65\x63" +
		"\x6F\x6D\x6D\x65\x6E\x64\x61\x74\x69\x6F\x6E\x73\x2E\x6A\x73\x6F" +
		"\x6E\x55\x54\x05\x00\x03\x25\xCB\xEE\x5C\x75\x78\x0B\x00\x01\x04" +
		"\xE8\x03\x00\x00\x04\xE8\x03\x00\x00\x50\x4B\x01\x02\x1E\x03\x0A" +
		"\x00\x00\x00\x00\x00\xA7\xA0\x69\x4D\x7D\xB5\xAF\x6B\x37\x00\x00" +
		"\x00\x37\x00\x00\x00\x08\x00\x18\x00\x00\x00\x00\x00\x01\x00\x00" +
		"\x00\xA4\x81\x8E\x01\x00\x00\x74\x65\x73\x74\x2E\x74\x78\x74\x55" +
		"\x54\x05\x00\x03\xCA\x2E\xE6\x5B\x75\x78\x0B\x00\x01\x04\xE8\x03" +
		"\x00\x00\x04\xE8\x03\x00\x00\x50\x4B\x05\x06\x00\x00\x00\x00\x03" +
		"\x00\x03\x00\x00\x01\x00\x00\x07\x02\x00\x00\x00\x00")

// this is unsignedWithRec with signed with:
// go run client.go
//
// and converted with:
// hexdump -v -e '16/1 "_x%02X" "\n"' /tmp/fakeapk/fakeapk.zip | sed 's/_/\\/g; s/\\x  //g; s/.*/    "&"/'
var signedWithRec = []byte("")
