package naming

import "testing"

func TestNormalizeLabel(t *testing.T) {
	if got := NormalizeLabel(" Jellyfin__Media! "); got != "jellyfin-media" {
		t.Fatalf("got %q", got)
	}
}
func TestSuffixHostCollision(t *testing.T) {
	e := Engine{Zone: "home.arpa", CollisionStrategy: "suffix-host"}
	got, err := e.Suggest("Jellyfin", "media", map[string]bool{"jellyfin.home.arpa": true})
	if err != nil || got != "jellyfin-media.home.arpa" {
		t.Fatalf("got %q, %v", got, err)
	}
}
