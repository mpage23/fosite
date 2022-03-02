package jwt

import (
	"testing"
	"time"
)

// Test taken from taken from [here](https://raw.githubusercontent.com/form3tech-oss/jwt-go/master/map_claims_test.go).
func Test_mapClaims_list_aud(t *testing.T) {
	mapClaims := MapClaims{
		"aud": []string{"foo"},
	}
	want := true
	got := mapClaims.VerifyAudience("foo", true)

	if want != got {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, got)
	}
}

// This is a custom test to check that an empty
// list with require == false returns valid
func Test_mapClaims_empty_list_aud(t *testing.T) {
	mapClaims := MapClaims{
		"aud": []string{},
	}
	want := true
	got := mapClaims.VerifyAudience("foo", false)

	if want != got {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, got)
	}
}
func Test_mapClaims_list_interface_aud(t *testing.T) {
	mapClaims := MapClaims{
		"aud": []interface{}{"foo"},
	}
	want := true
	got := mapClaims.VerifyAudience("foo", true)

	if want != got {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, got)
	}
}
func Test_mapClaims_string_aud(t *testing.T) {
	mapClaims := MapClaims{
		"aud": "foo",
	}
	want := true
	got := mapClaims.VerifyAudience("foo", true)

	if want != got {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, got)
	}
}

func Test_mapClaims_list_aud_no_match(t *testing.T) {
	mapClaims := MapClaims{
		"aud": []string{"bar"},
	}
	want := false
	got := mapClaims.VerifyAudience("foo", true)

	if want != got {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, got)
	}
}
func Test_mapClaims_string_aud_fail(t *testing.T) {
	mapClaims := MapClaims{
		"aud": "bar",
	}
	want := false
	got := mapClaims.VerifyAudience("foo", true)

	if want != got {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, got)
	}
}

func Test_mapClaims_string_aud_no_claim(t *testing.T) {
	mapClaims := MapClaims{}
	want := false
	got := mapClaims.VerifyAudience("foo", true)

	if want != got {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, got)
	}
}

func Test_mapClaims_string_aud_no_claim_not_required(t *testing.T) {
	mapClaims := MapClaims{}
	want := false
	got := mapClaims.VerifyAudience("foo", false)

	if want != got {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", want, got)
	}
}

// Test clock skew (default 10s) allows request to succeed for small time variations
func Test_mapClaims_iat_time_in_near_future(t *testing.T) {
	now := time.Now().Unix()
	mapClaims := MapClaims{
		"iat": now + 5,
		"exp": now - 5,
		"nbf": now + 5,
	}
	err := mapClaims.Valid()

	if err != nil {
		t.Fatalf("Failed to verify claims, expected no error and got: %v", err)
	}
}

// Test that validation fails for times beyond the allowed clock skew
func Test_mapClaims_iat_time_in_distant_future(t *testing.T) {
	now := time.Now().Unix()
	mapClaims := MapClaims{
		"iat": now + 3600,
	}

	err := mapClaims.Valid()

	if err == nil {
		t.Fatalf("Failed to verify claims, expected error and call succeeded")
	}
}