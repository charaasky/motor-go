package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcCommSelf(t *testing.T) {
	comm, ok := procComm(uint32(os.Getpid()))
	if !ok || comm == "" {
		t.Fatalf("procComm(self) = %q, %v", comm, ok)
	}
}

func TestProcUIDsSelf(t *testing.T) {
	r, e, ok := procUIDs(uint32(os.Getpid()))
	if !ok {
		t.Fatal("procUIDs(self) no ok")
	}
	if r != os.Getuid() || e != os.Geteuid() {
		t.Fatalf("procUIDs(self) = %d,%d, want %d,%d", r, e, os.Getuid(), os.Geteuid())
	}
}

func TestProcExeSelf(t *testing.T) {
	exe, ok := procExe(uint32(os.Getpid()))
	if !ok || exe == "" {
		t.Fatalf("procExe(self) = %q, %v", exe, ok)
	}
}

func TestMatchSubjectProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	comm, _ := procComm(pid)

	// Sin restricción: todo permitido.
	subjectAllowed = map[string]bool{}
	if !matchSubjectProcess(pid, comm) {
		t.Fatal("sin restricción debería permitir")
	}

	// Permitido por comm.
	subjectAllowed = map[string]bool{comm: true}
	if !matchSubjectProcess(pid, comm) {
		t.Fatal("match por comm falló")
	}

	// Permitido por basename del exe (aunque comm no esté en el set).
	exe, _ := procExe(pid)
	base := filepath.Base(exe)
	subjectAllowed = map[string]bool{base: true}
	if !matchSubjectProcess(pid, "algún-comm-distinto") {
		t.Fatal("match por basename del exe falló")
	}

	// No permitido: comm y basename ajenos.
	subjectAllowed = map[string]bool{"binario-que-no-existe-xyz": true}
	if matchSubjectProcess(pid, "comm-que-no-existe-xyz") {
		t.Fatal("debería rechazar un binario ajeno al allowlist")
	}
}

func TestSha256FileSelf(t *testing.T) {
	exe, ok := procExe(uint32(os.Getpid()))
	if !ok {
		t.Fatal("procExe(self) no ok")
	}
	if _, ok := sha256File(exe); !ok {
		t.Fatal("sha256File(self) no ok")
	}
}
