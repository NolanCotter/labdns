package config

import "testing"

func TestRejectsLocalZone(t *testing.T) {
	c := Default()
	c.Domain.Zone = "local"
	if c.Validate() == nil {
		t.Fatal("expected invalid .local zone")
	}
}
func TestDefaultConfigIsValid(t *testing.T) {
	if e := Default().Validate(); e != nil {
		t.Fatal(e)
	}
}
