package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAntiRollback(t *testing.T) {
	policyStatePath = filepath.Join(t.TempDir(), "policy.serial")

	if got := currentPolicySerial(); got != 0 {
		t.Fatalf("estado inicial = %d, want 0", got)
	}
	persistPolicySerial(5)
	if got := currentPolicySerial(); got != 5 {
		t.Fatalf("tras persistir 5 = %d, want 5", got)
	}
	persistPolicySerial(3) // no debe bajar
	if got := currentPolicySerial(); got != 5 {
		t.Fatalf("tras persistir 3 = %d, want 5 (anti-rollback)", got)
	}
	persistPolicySerial(7)
	if got := currentPolicySerial(); got != 7 {
		t.Fatalf("tras persistir 7 = %d, want 7", got)
	}
	if _, err := os.Stat(policyStatePath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("quedó residuo .tmp tras el rename")
	}
}
