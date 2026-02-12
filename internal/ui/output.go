package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/capsaicin/scanner/internal/config"
	"github.com/capsaicin/scanner/internal/scanner"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	italic = "\033[3m"

	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"

	bgRed     = "\033[41m"
	bgGreen   = "\033[42m"
	bgYellow  = "\033[43m"
	bgBlue    = "\033[44m"
	bgMagenta = "\033[45m"
	bgCyan    = "\033[46m"
)

func PrintBanner() {
	fmt.Println()
	fmt.Printf("%s%s", bold, red)
	fmt.Println("   ╔═══════════════════════════════════════════╗")
	fmt.Println("   ║                                           ║")
	fmt.Printf("   ║   🌶  %sCAPSAICIN%s%s%s  v3.0                   ║\n", white, reset, bold, red)
	fmt.Println("   ║   Web Directory Scanner                   ║")
	fmt.Println("   ║                                           ║")
	fmt.Println("   ╚═══════════════════════════════════════════╝")
	fmt.Printf("%s\n", reset)
}

func PrintConfig(cfg config.Config, targetCount int) {
	fmt.Printf("\n%s%s ⚙  Scan Configuration%s\n", bold, cyan, reset)
	fmt.Printf("%s───────────────────────────────%s\n", dim, reset)
	fmt.Printf("  %sTargets%s     %s%d%s\n", dim, reset, white, targetCount, reset)
	fmt.Printf("  %sThreads%s     %s%d%s\n", dim, reset, white, cfg.Threads, reset)
	fmt.Printf("  %sTimeout%s     %s%ds%s\n", dim, reset, white, cfg.Timeout, reset)
	fmt.Printf("  %sWordlist%s    %s%s%s\n", dim, reset, white, cfg.Wordlist, reset)
	if cfg.RateLimit > 0 {
		fmt.Printf("  %sRate Limit%s  %s%d req/s%s\n", dim, reset, white, cfg.RateLimit, reset)
	}
	if cfg.MaxDepth > 0 {
		fmt.Printf("  %sMax Depth%s   %s%d%s\n", dim, reset, white, cfg.MaxDepth, reset)
	}
	if len(cfg.Extensions) > 0 {
		fmt.Printf("  %sExtensions%s  %s%s%s\n", dim, reset, white, strings.Join(cfg.Extensions, ", "), reset)
	}
	if cfg.SafeMode {
		fmt.Printf("  %sMode%s        %s%sSafe Mode%s\n", dim, reset, bold, yellow, reset)
	}
	fmt.Println()
}

func PrintResult(result scanner.Result) {
	statusColor := statusToColor(result.StatusCode)
	statusBg := statusToBg(result.StatusCode)

	badge := fmt.Sprintf(" %s%s %d %s", bold, statusBg, result.StatusCode, reset)

	var tags []string

	if result.Critical {
		tags = append(tags, fmt.Sprintf("%s%s CRITICAL %s", bold, bgRed, reset))
	}

	if result.SecretFound {
		tags = append(tags, fmt.Sprintf("%s%s 🔑 SECRET %s", bold, bgMagenta, reset))
	}

	if result.WAFDetected != "" {
		tags = append(tags, fmt.Sprintf("%s%s 🛡 %s %s", bold, bgYellow, result.WAFDetected, reset))
	}

	if result.Method != "GET" {
		tags = append(tags, fmt.Sprintf("%s%s%s%s", dim, cyan, result.Method, reset))
	}

	sizeStr := formatSize(result.Size)

	tagStr := ""
	if len(tags) > 0 {
		tagStr = "  " + strings.Join(tags, " ")
	}

	fmt.Printf("%s  %s%s%s  %s%s%s%s\n",
		badge,
		dim, sizeStr, reset,
		statusColor, result.URL, reset,
		tagStr)
}

func StartProgressReporter(stats *scanner.Stats, ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	frame := 0

	for {
		select {
		case <-ctx.Done():
			fmt.Print("\r\033[K")
			return
		case <-ticker.C:
			elapsed := time.Since(stats.StartTime).Seconds()
			if elapsed == 0 {
				elapsed = 1
			}
			reqPerSec := float64(stats.GetProcessed()) / elapsed
			total := stats.GetTotal()
			processed := stats.GetProcessed()
			var progress float64
			if total > 0 {
				progress = float64(processed) / float64(total) * 100
			}

			barWidth := 20
			filled := int(progress / 100 * float64(barWidth))
			if filled > barWidth {
				filled = barWidth
			}
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

			s := spinner[frame%len(spinner)]
			frame++

			found := stats.GetFound()
			secrets := stats.GetSecrets()
			wafHits := stats.GetWAFHits()
			errors := stats.GetErrors()

			foundStr := fmt.Sprintf("%s%d%s", green, found, reset)
			secretStr := ""
			if secrets > 0 {
				secretStr = fmt.Sprintf("  %s🔑 %d%s", magenta, secrets, reset)
			}
			wafStr := ""
			if wafHits > 0 {
				wafStr = fmt.Sprintf("  %s🛡 %d%s", yellow, wafHits, reset)
			}
			errStr := ""
			if errors > 0 {
				errStr = fmt.Sprintf("  %s✗ %d%s", red, errors, reset)
			}

			fmt.Printf("\r  %s%s %s%s%s %s%.0f%%%s  %s%d%s req/s  Found: %s%s%s%s",
				cyan, s,
				dim, bar, reset,
				bold, progress, reset,
				dim, int(reqPerSec), reset,
				foundStr,
				secretStr, wafStr, errStr)
		}
	}
}

func PrintSummary(stats *scanner.Stats) {
	elapsed := time.Since(stats.StartTime)
	reqPerSec := float64(stats.GetProcessed()) / elapsed.Seconds()

	fmt.Println()
	fmt.Printf("\n%s%s ✔  Scan Complete%s\n", bold, green, reset)
	fmt.Printf("%s───────────────────────────────%s\n", dim, reset)

	fmt.Printf("  %sRequests%s    %s%d%s\n", dim, reset, white, stats.GetProcessed(), reset)
	fmt.Printf("  %sFindings%s    %s%s%d%s\n", dim, reset, bold, green, stats.GetFound(), reset)

	if stats.GetSecrets() > 0 {
		fmt.Printf("  %sSecrets%s     %s%s%d%s\n", dim, reset, bold, magenta, stats.GetSecrets(), reset)
	}
	if stats.GetWAFHits() > 0 {
		fmt.Printf("  %sWAF Hits%s    %s%s%d%s\n", dim, reset, bold, yellow, stats.GetWAFHits(), reset)
	}
	if stats.GetErrors() > 0 {
		fmt.Printf("  %sErrors%s      %s%s%d%s\n", dim, reset, bold, red, stats.GetErrors(), reset)
	}

	fmt.Printf("  %sDuration%s    %s%s%s\n", dim, reset, white, elapsed.Round(time.Millisecond), reset)
	fmt.Printf("  %sSpeed%s       %s%.0f req/s%s\n", dim, reset, white, reqPerSec, reset)
	fmt.Println()
}

func statusToColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return green
	case code >= 300 && code < 400:
		return blue
	case code >= 400 && code < 500:
		return red
	case code >= 500:
		return yellow
	default:
		return white
	}
}

func statusToBg(code int) string {
	switch {
	case code >= 200 && code < 300:
		return bgGreen
	case code >= 300 && code < 400:
		return bgBlue
	case code >= 400 && code < 500:
		return bgRed
	case code >= 500:
		return bgYellow
	default:
		return ""
	}
}

func formatSize(bytes int) string {
	switch {
	case bytes >= 1024*1024:
		return fmt.Sprintf("%5.1fMB", float64(bytes)/1024/1024)
	case bytes >= 1024:
		return fmt.Sprintf("%5.1fKB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%6dB", bytes)
	}
}
