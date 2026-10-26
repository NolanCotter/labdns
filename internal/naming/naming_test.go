package naming

import (
	"strings"
	"testing"
)

func TestNormalizeLabel(t *testing.T) {
	cases := map[string]string{
		" Jellyfin__Media! ":    "jellyfin-media",
		"---":                   "",
		"Über Service":          "über-service",
		"a.b.c":                 "a-b-c",
		"already-valid":         "already-valid",
		"UPPER_case-and-dashes": "upper-case-and-dashes",
	}
	for in, want := range cases {
		if got := NormalizeLabel(in); got != want {
			t.Fatalf("NormalizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
func TestSuffixHostCollision(t *testing.T) {
	e := Engine{Zone: "home.arpa", CollisionStrategy: "suffix-host"}
	got, err := e.Suggest("Jellyfin", "media", map[string]bool{"jellyfin.home.arpa": true})
	if err != nil || got != "jellyfin-media.home.arpa" {
		t.Fatalf("got %q, %v", got, err)
	}
}
func TestNumericSuffixCollision(t *testing.T) {
	e := Engine{Zone: "home.arpa", CollisionStrategy: "numeric-suffix"}
	got, err := e.Suggest("jellyfin", "media", map[string]bool{"jellyfin.home.arpa": true})
	if err != nil || got != "jellyfin-2.home.arpa" {
		t.Fatalf("got %q, %v", got, err)
	}
}
func TestSuffixHostFallsBackToNumeric(t *testing.T) {
	e := Engine{Zone: "home.arpa", CollisionStrategy: "suffix-host"}
	used := map[string]bool{"jellyfin.home.arpa": true, "jellyfin-media.home.arpa": true}
	got, err := e.Suggest("jellyfin", "media", used)
	if err != nil || got != "jellyfin-2.home.arpa" {
		t.Fatalf("got %q, %v", got, err)
	}
}
func TestRejectsEmptyName(t *testing.T) {
	e := Engine{Zone: "home.arpa", CollisionStrategy: "suffix-host"}
	if _, err := e.Suggest("!!!", "media", map[string]bool{}); err == nil {
		t.Fatal("expected error")
	}
}
func TestTruncatesLongLabel(t *testing.T) {
	e := Engine{Zone: "home.arpa", CollisionStrategy: "suffix-host"}
	got, err := e.Suggest(strings.Repeat("a", 100), "media", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	label := strings.Split(got, ".")[0]
	if len(label) != 63 {
		t.Fatalf("label length = %d, want 63 (%q)", len(label), got)
	}
}
func TestCollisionWithoutStrategy(t *testing.T) {
	e := Engine{Zone: "home.arpa"}
	if _, err := e.Suggest("jellyfin", "media", map[string]bool{"jellyfin.home.arpa": true}); err == nil {
		t.Fatal("expected collision error")
	}
}
