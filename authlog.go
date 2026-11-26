package main

// authlog.go — paridad con el log de Seguridad de Windows (Fase 3).
// Hace tail de /var/log/auth.log (o /var/log/secure) y detecta:
//   - logons fallidos (fuerza bruta correlacionada por IP)
//   - sudo (escalada de privilegios)
//   - useradd/groupadd (persistencia de cuentas)
//
// Es el equivalente Linux de los eventos 4625/4672/4720 del log Security.

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var authLogPath string

func init() {
	flag.StringVar(&authLogPath, "authlog", "", "ruta del log de autenticación (auth.log/secure); vacío = autodetectar")
}

var (
	reFailedPass = regexp.MustCompile(`(?i)Failed password for (?:invalid user )?(\S+) from ([\d.]+)`)
	reAuthFail   = regexp.MustCompile(`(?i)authentication failure.*rhost=([\d.]+)`)
	reSudo       = regexp.MustCompile(`(?i)sudo:\s+\S+\s*:.*COMMAND=(.+)`)
	reNewUser    = regexp.MustCompile(`(?i)new user: name=(\S+)`)
	reUserAdd    = regexp.MustCompile(`(?i)useradd\[\d+\]: new user name=(\S+)`)
	reGroupAdd   = regexp.MustCompile(`(?i)groupadd\[\d+\]: group added`)
	reRepeated   = regexp.MustCompile(`message repeated (\d+) times: \[ (.*)]$`)
)

type authFailBucket struct {
	times []time.Time
}

var (
	authFailsMu sync.Mutex
	authFails   = map[string]*authFailBucket{}
)

func detectAuthLog() string {
	if authLogPath != "" {
		return authLogPath
	}
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// startAuthLog vigila el log de autenticación por polling (maneja rotación).
func startAuthLog() {
	path := detectAuthLog()
	if path == "" {
		return
	}
	var offset int64
	if fi, err := os.Stat(path); err == nil {
		offset = fi.Size() // arrancar desde el final: solo eventos nuevos
	}
	log.Printf("authlog activo en %s (logons fallidos, sudo, useradd)", path)

	go func() {
		for {
			time.Sleep(1 * time.Second)
			fi, err := os.Stat(path)
			if err != nil {
				continue
			}
			if fi.Size() < offset {
				offset = 0 // rotación (logrotate): releer el archivo nuevo
			}
			if fi.Size() == offset {
				continue
			}
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}
			rd := bufio.NewReader(f)
			for {
				line, err := rd.ReadString('\n')
				if err != nil {
					break
				}
				processAuthLine(strings.TrimSpace(line))
			}
			offset, _ = f.Seek(0, io.SeekCurrent)
			f.Close()
		}
	}()
}

func processAuthLine(line string) {
	now := time.Now()
	// rsyslog colapsa mensajes idénticos en "message repeated N times";
	// hay que expandirlos para no subcontar la fuerza bruta.
	if m := reRepeated.FindStringSubmatch(line); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil || n <= 0 {
			n = 1
		}
		inner := m[2]
		for i := 0; i < n; i++ {
			processAuthMsg(inner, now)
		}
		return
	}
	processAuthMsg(line, now)
}

func processAuthMsg(line string, now time.Time) {
	switch {
	case reFailedPass.MatchString(line):
		m := reFailedPass.FindStringSubmatch(line)
		user, ip := m[1], m[2]
		emit("AUTH_LOGON_FALLIDO", "auth", fmt.Sprintf("user=%s src=%s", user, ip))
		observeAuthFail(ip, now)
	case reAuthFail.MatchString(line):
		m := reAuthFail.FindStringSubmatch(line)
		observeAuthFail(m[1], now)
	case reSudo.MatchString(line):
		m := reSudo.FindStringSubmatch(line)
		cmd := strings.TrimSpace(m[1])
		emit("AUTH_SUDO", "sudo", fmt.Sprintf("cmd=%.120q", cmd))
	case reNewUser.MatchString(line):
		m := reNewUser.FindStringSubmatch(line)
		emit("AUTH_NUEVO_USUARIO", "useradd", fmt.Sprintf("user=%s", m[1]))
	case reUserAdd.MatchString(line):
		m := reUserAdd.FindStringSubmatch(line)
		emit("AUTH_NUEVO_USUARIO", "useradd", fmt.Sprintf("user=%s", m[1]))
	case reGroupAdd.MatchString(line):
		emit("AUTH_NUEVO_GRUPO", "groupadd", "")
	}
}

func observeAuthFail(ip string, now time.Time) {
	authFailsMu.Lock()
	defer authFailsMu.Unlock()
	b := authFails[ip]
	if b == nil {
		b = &authFailBucket{}
		authFails[ip] = b
	}
	b.times = append(b.times, now)
	cutoff := now.Add(-60 * time.Second)
	kept := b.times[:0]
	for _, t := range b.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.times = kept
	if len(b.times) >= 5 {
		delete(authFails, ip)
		emit("AUTH_FUERZA_BRUTA", "auth", fmt.Sprintf("src=%s intentos=5", ip))
	}
}
