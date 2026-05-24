from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BENCHMARK_DIR.parent
RUNS_DIR = BENCHMARK_DIR / "runs"
GENERATED_DIR = BENCHMARK_DIR / "generated"


def ensure_layout():
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
