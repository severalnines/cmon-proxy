package config

import "testing"

func TestApplyWebServerSecurityDefaults_CustomFrameOptionsValue(t *testing.T) {
	t.Run("default is SAMEORIGIN so cmon-ssh hterm can load its iframe", func(t *testing.T) {
		sec := &WebServerSecurity{}
		applyWebServerSecurityDefaults(sec)
		if sec.CustomFrameOptionsValue != "SAMEORIGIN" {
			t.Fatalf("CustomFrameOptionsValue = %q, want SAMEORIGIN", sec.CustomFrameOptionsValue)
		}
	})

	t.Run("user-provided value is preserved", func(t *testing.T) {
		sec := &WebServerSecurity{CustomFrameOptionsValue: "DENY"}
		applyWebServerSecurityDefaults(sec)
		if sec.CustomFrameOptionsValue != "DENY" {
			t.Fatalf("CustomFrameOptionsValue = %q, want DENY", sec.CustomFrameOptionsValue)
		}
	})
}
