from fabric import task

from tychebench.results import print_latest_summary
from tychebench.runner import BenchError, run_aws, run_local


def _run_or_exit(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except BenchError as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1) from None


@task
def local(
    ctx,
    nodes=8,
    epochs=1000,
    protocols="tyche,tyche-reconfig,asyrand,grandline,spurt",
    out="",
    fault_threshold="",
):
    """Run the local in-memory beacon benchmark."""
    _run_or_exit(
        run_local,
        n=int(nodes),
        epochs=int(epochs),
        protocols=protocols,
        out_root=out or None,
        fault_threshold=int(fault_threshold) if str(fault_threshold).strip() else None,
    )


@task
def aws(
    ctx,
    machines=4,
    nodes=8,
    epochs=200,
    protocols="tyche,asyrand,grandline,spurt",
    out="",
):
    """Run the AWS TCP beacon benchmark."""
    _run_or_exit(
        run_aws,
        machines=int(machines),
        nodes=int(nodes),
        epochs=int(epochs),
        protocols=protocols,
        out_root=out or None,
    )


@task
def logs(ctx, run=""):
    """Print a compact summary for a benchmark run directory."""
    print_latest_summary(run or None)
