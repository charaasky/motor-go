package main

// Detección de T1036.011 (Overwrite Process Arguments / suplantación de nombre
// de proceso vía prctl PR_SET_NAME). Un proceso de USUARIO que renombra su comm
// a un nombre de hilo de kernel (con corchetes, p. ej. [kworker/0:0]) intenta
// camuflarse en ps/top. Se detecta escaneando /proc periódicamente: un hilo de
// kernel real NO tiene /proc/PID/exe; si el comm lleva corchetes pero el exe
// existe, es suplantación.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func scanArgvSpoof(stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			entries, err := os.ReadDir("/proc")
			if err != nil {
				continue
			}
			for _, e := range entries {
				pid, err := strconv.Atoi(e.Name())
				if err != nil {
					continue
				}
				commB, err := os.ReadFile("/proc/" + e.Name() + "/comm")
				if err != nil {
					continue
				}
				comm := strings.TrimSpace(string(commB))
				if !strings.HasPrefix(comm, "[") || !strings.HasSuffix(comm, "]") {
					continue
				}
				exe, err := os.Readlink("/proc/" + e.Name() + "/exe")
				if err == nil && exe != "" {
					emitProc("ARGV_SPOOF (T1036.011)", comm, uint32(pid),
						fmt.Sprintf("proceso usuario con comm de kernel: exe=%s", exe))
				}
			}
		}
	}
}
