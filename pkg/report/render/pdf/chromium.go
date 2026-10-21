package pdf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	htmlrender "github.com/Aadil-Nabi/kvcbom/pkg/report/render/html"

	"github.com/Aadil-Nabi/kvcbom/pkg/report"
)

// Chromium renders the self-contained HTML to PDF using a locally installed headless
// browser. It is opt-in (`--pdf-engine chromium`) because it needs a browser present and
// its output is not byte-deterministic; when no browser is found Render fails with a clear
// message (SPEC §9 permits this). It runs the browser with networking disabled.
type Chromium struct {
	// Binary overrides browser discovery (used by tests); empty means auto-detect.
	Binary string
}

// Name identifies the engine.
func (Chromium) Name() string { return "chromium" }

// candidateBinaries lists the browser executables to look for, in order of preference.
func candidateBinaries() []string {
	if runtime.GOOS == "windows" {
		return []string{"chrome.exe", "chrome", "msedge.exe", "msedge", "chromium.exe", "chromium"}
	}
	return []string{
		"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
		"chrome", "microsoft-edge", "msedge",
	}
}

func (c Chromium) resolve() (string, bool) {
	if c.Binary != "" {
		return c.Binary, true
	}
	for _, name := range candidateBinaries() {
		if p, err := exec.LookPath(name); err == nil {
			return p, true
		}
	}
	// A few common fixed install locations that are not always on PATH.
	for _, p := range fixedPaths() {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	return "", false
}

// Available reports whether a browser was found.
func (c Chromium) Available() (bool, string) {
	if bin, ok := c.resolve(); ok {
		return true, bin
	}
	return false, "no Chromium/Chrome/Edge executable found on PATH; install one or use --pdf-engine purego"
}

// Render writes the HTML to a temp file and prints it to PDF with headless Chromium.
func (c Chromium) Render(r *report.Report, w io.Writer) error {
	bin, ok := c.resolve()
	if !ok {
		_, msg := c.Available()
		return fmt.Errorf("chromium PDF engine unavailable: %s", msg)
	}

	dir, err := os.MkdirTemp("", "kvcbom-pdf-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	htmlPath := filepath.Join(dir, "report.html")
	outPath := filepath.Join(dir, "report.pdf")

	var html bytes.Buffer
	if err := (htmlrender.Renderer{}).Render(r, &html); err != nil {
		return err
	}
	if err := os.WriteFile(htmlPath, html.Bytes(), 0o600); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{
		"--headless=new", "--disable-gpu", "--no-sandbox",
		"--no-pdf-header-footer", "--disable-networking",
		"--print-to-pdf=" + outPath,
		"file://" + filepath.ToSlash(htmlPath),
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Older browsers reject --headless=new; retry once with the legacy flag.
		args[0] = "--headless"
		cmd = exec.CommandContext(ctx, bin, args...)
		cmd.Stderr = &stderr
		if err2 := cmd.Run(); err2 != nil {
			return fmt.Errorf("headless browser failed to print PDF: %w: %s", err2, stderr.String())
		}
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return fmt.Errorf("browser produced no PDF: %w", err)
	}
	_, err = w.Write(data)
	return err
}

// fixedPaths lists common browser install locations not always present on PATH.
func fixedPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		}
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		}
	default:
		return []string{"/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium"}
	}
}
