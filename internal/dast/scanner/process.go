package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const maxOutputBytes = 16 << 20

var errOutputLimit = errors.New("engine output exceeds limit")

type boundedOutput struct {
	bytes.Buffer
	limit  int
	cancel context.CancelFunc
	err    error
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.err = errOutputLimit
		b.cancel()
		return 0, b.err
	}
	return b.Buffer.Write(p)
}

func runEngine(ctx context.Context, path string, args []string, maxOutput int) (output []byte, err error) {
	runtimeDir, err := os.MkdirTemp("", "dast-engine-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(runtimeDir)) }()
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := &boundedOutput{limit: maxOutput, cancel: cancel}
	stderr := &boundedOutput{limit: maxOutput, cancel: cancel}
	cmd := exec.CommandContext(processCtx, path, args...)
	cmd.Dir = runtimeDir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "LANG=C",
		"NUCLEI_CONFIG_DIR=" + runtimeDir, "XDG_CONFIG_HOME=" + runtimeDir,
		"XDG_DATA_HOME=" + runtimeDir, "XDG_CACHE_HOME=" + runtimeDir, "XDG_STATE_HOME=" + runtimeDir,
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 3 * time.Second
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	runErr := cmd.Run()
	var cleanupErr error
	if cmd.Process != nil {
		cleanupErr = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(cleanupErr, syscall.ESRCH) {
			cleanupErr = nil
		}
	}
	err = errors.Join(runErr, cleanupErr, stdout.err, stderr.err, ctx.Err())
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("engine %s: %w; stderr: %s", path, err, stderr.String())
	}
	return stdout.Bytes(), nil
}
