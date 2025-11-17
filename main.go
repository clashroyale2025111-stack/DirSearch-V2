package main

import (
    "bufio"
    "fmt"
	"flag"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"
)

type Result struct {
    Mode       string `json:"mode"`
    Target     string `json:"target"`
    FinalURL   string `json:"final_url"`
    StatusCode int    `json:"status_code"`
    DurationMs int64  `json:"duration_ms"`
    BodyLength int    `json:"body_length"`
    BodySample string `json:"body_sample"`
    Err        string `json:"error,omitempty"`
}

func main() {
    mode := flag.String("mode", "", "dir or ssrf")
    target := flag.String("target", "", "target domain or URL")
    endpoint := flag.String("endpoint", "", "SSRF endpoint template with {TARGET}")
    targetsFile := flag.String("targets", "", "File containing internal SSRF targets")
    flag.Parse()

    if *mode == "" {
        fmt.Println("Usage Examples:")
        fmt.Println("  recon.exe -mode dir -target chatgpt.com")
        fmt.Println("  recon.exe -mode ssrf -endpoint \"https://victim/ssrf?url={TARGET}\" -targets targets.txt")
        return
    }

    client := &http.Client{Timeout: 10 * time.Second}

    switch *mode {
    case "dir":
        if *target == "" {
            fmt.Println("Missing -target")
            return
        }
        runDirEnumMode(client, *target)

    case "ssrf":
        if *endpoint == "" || *targetsFile == "" {
            fmt.Println("Missing -endpoint or -targets")
            return
        }
        ssrfTargets, err := loadLines(*targetsFile)
        if err != nil {
            fmt.Println("Failed to load targets:", err)
            return
        }
        runSSRFMode(client, *endpoint, ssrfTargets)

    default:
        fmt.Println("Unknown mode. Use: dir or ssrf")
    }
}

func runDirEnumMode(client *http.Client, domain string) {
    words, err := loadLines("wordlist.txt")
    if err != nil {
        fmt.Println("wordlist.txt not found in folder.")
        return
    }

    base := domain
    if !strings.HasPrefix(domain, "http") {
        base = "https://" + domain
    }

    fmt.Printf("[*] Scanning %s using %d words...\n", base, len(words))

    results := runDirEnum(client, base, words, 50)
    printTable(results)
}

func runSSRFMode(client *http.Client, endpoint string, targets []string) {
    fmt.Printf("[*] Running SSRF mode using %d targets...\n", len(targets))
    results := runSSRFFromTargets(client, endpoint, targets, 10)
    printTable(results)
}

func runDirEnum(client *http.Client, base string, words []string, concurrency int) []Result {
    jobs := make(chan string)
    resultsCh := make(chan Result)
    var wg sync.WaitGroup

    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for w := range jobs {
                res, ok := probeDir(client, base, w)
                if ok {
                    resultsCh <- res
                }
            }
        }()
    }

    go func() {
        wg.Wait()
        close(resultsCh)
    }()

    go func() {
        for _, w := range words {
            jobs <- w
        }
        close(jobs)
    }()

    var results []Result
    for r := range resultsCh {
        results = append(results, r)
    }

    return results
}

func probeDir(client *http.Client, base, word string) (Result, bool) {
    url := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(word, "/")

    req, _ := http.NewRequest("GET", url, nil)
    start := time.Now()
    resp, err := client.Do(req)
    duration := time.Since(start)

    if err != nil {
        return Result{}, false
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return Result{}, false
    }

    buf := make([]byte, 1024)
    n, _ := resp.Body.Read(buf)

    return Result{
        Mode:       "dir",
        Target:     word,
        FinalURL:   url,
        StatusCode: resp.StatusCode,
        DurationMs: duration.Milliseconds(),
        BodyLength: n,
        BodySample: sanitize(string(buf[:n])),
    }, true
}

func runSSRFFromTargets(client *http.Client, endpoint string, targets []string, concurrency int) []Result {
    jobs := make(chan string)
    resultsCh := make(chan Result)
    var wg sync.WaitGroup

    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for t := range jobs {
                resultsCh <- probeSSRF(client, endpoint, t)
            }
        }()
    }

    go func() {
        wg.Wait()
        close(resultsCh)
    }()

    go func() {
        for _, t := range targets {
            jobs <- t
        }
        close(jobs)
    }()

    var results []Result
    for r := range resultsCh {
        results = append(results, r)
    }

    return results
}

func probeSSRF(client *http.Client, endpoint, target string) Result {
    finalURL := strings.Replace(endpoint, "{TARGET}", url.QueryEscape(target), 1)

    req, _ := http.NewRequest("GET", finalURL, nil)
    start := time.Now()
    resp, err := client.Do(req)
    duration := time.Since(start)

    if err != nil {
        return Result{
            Mode:       "ssrf",
            Target:     target,
            FinalURL:   finalURL,
            DurationMs: duration.Milliseconds(),
            Err:        err.Error(),
        }
    }
    defer resp.Body.Close()

    buf := make([]byte, 2048)
    n, _ := resp.Body.Read(buf)

    return Result{
        Mode:       "ssrf",
        Target:     target,
        FinalURL:   finalURL,
        StatusCode: resp.StatusCode,
        DurationMs: duration.Milliseconds(),
        BodyLength: n,
        BodySample: sanitize(string(buf[:n])),
    }
}

func sanitize(s string) string {
    s = strings.ReplaceAll(s, "\n", " ")
    s = strings.ReplaceAll(s, "\r", " ")
    if len(s) > 200 {
        s = s[:200] + "..."
    }
    return s
}

func loadLines(path string) ([]string, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var lines []string
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" && !strings.HasPrefix(line, "#") {
            lines = append(lines, line)
        }
    }
    return lines, scanner.Err()
}

func printTable(results []Result) {
    fmt.Printf("\n%-4s %-6s %-8s %-10s %-20s %-s\n",
        "MODE", "CODE", "TIME", "SIZE", "TARGET", "SAMPLE")
    fmt.Println(strings.Repeat("-", 110))

    for _, r := range results {
        fmt.Printf("%-4s %-6d %-8d %-10d %-20s %-s\n",
            r.Mode, r.StatusCode, r.DurationMs, r.BodyLength, r.Target, r.BodySample)
    }
}