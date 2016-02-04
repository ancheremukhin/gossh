package main

import (
    "os"
    "fmt"
    "net"
    "strings"
    "syscall"
    "bufio"
    "bytes"
    "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ssh/terminal"
    "golang.org/x/crypto/ssh/agent"
)

const (
    BATCH_SIZE = 32
    PORT = 22
)

func main() {

    if len(os.Args) < 2 {
        fmt.Fprintln(os.Stderr, "Usage: gossh <command> ... ")
        syscall.Exit(1)
    }

    fmt.Println("Executing", os.Args[1], "...")

    command := fmt.Sprintf("%s\n", os.Args[1])
    ips := make([]string, 0)

    if terminal.IsTerminal(syscall.Stdin) {
    } else {
        scanner := bufio.NewScanner(os.Stdin)
        scanner.Split(bufio.ScanWords)
        for scanner.Scan() {
            ips = append(ips, scanner.Text())
        }
    }

    sshConfig := &ssh.ClientConfig{
        User: os.Getenv("LOGNAME"),
        Auth: []ssh.AuthMethod{SSHAgent()},
    }

    pos := 0
    for pos < len(ips) {
        end := pos + BATCH_SIZE
        if end > len(ips) {
            end = len(ips)
        }

        responses, _ := execute(command, ips[pos:end], sshConfig)
        for _, r := range responses {
            fmt.Println(r)
        }

        pos = end
    }
}

func SSHAgent() ssh.AuthMethod {
    if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
        return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
    }
    return nil
}

func execute(command string, ips []string,  config *ssh.ClientConfig) ([]string, error) {
    var ch = make(chan string, len(ips))
    for _, ip := range ips {
        go func(ip string) {
            conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", ip, PORT), config)
            if err != nil {
                ch <- fmt.Sprintf("Failed to connect to %s", ip)
                return
            }
            defer conn.Close()

            session, err := conn.NewSession()
            if err != nil {
                ch <- fmt.Sprintf("Failed to create session %s", ip)
                return
            }
            defer session.Close()

            var stdoutBuf bytes.Buffer
            session.Stdout = &stdoutBuf
            session.Run(command)
            
            ch <- fmt.Sprintf("%s %s", ip, stdoutBuf.String())

        }(ip)
    }

    var responses = make([]string, 0, len(ips))
    for _ = range ips {
        r := <- ch
        responses = append(responses, strings.Trim(r, "\n "))
    }

    return responses, nil
}
