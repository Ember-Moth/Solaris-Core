"""Expose partial output when an integration test child fails to drain."""
import subprocess


def run(*args, **kwargs):
    try:
        return subprocess.run(*args, **kwargs)
    except subprocess.TimeoutExpired as exc:
        def text(output):
            return output.decode(errors="replace") if isinstance(output, bytes) else (output or "")
        raise RuntimeError(f"{exc}\nchild stdout: {text(exc.stdout)}\nchild stderr: {text(exc.stderr)}") from exc
