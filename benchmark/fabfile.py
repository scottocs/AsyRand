from fabric import task

from tychebench.results import print_latest_summary
from tychebench.errors import BenchError
from tychebench.runner import run_aws, run_local
from tychebench.aws import (
    create_instances,
    destroy_instances,
    print_info,
    start_instances,
    stop_instances,
)


def _run_or_exit(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except BenchError as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1) from None
    except Exception as exc:
        print(f"ERROR: unexpected failure: {type(exc).__name__}: {exc}")
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
    nodes=8,
    epochs=200,
    protocols="tyche,asyrand,grandline,spurt",
    out="",
    key_path="",
    remote_dir="TycheBench",
    ssh_user="",
):
    """Run the AWS TCP beacon benchmark."""
    _run_or_exit(
        run_aws,
        nodes=int(nodes),
        epochs=int(epochs),
        protocols=protocols,
        out_root=out or None,
        key_path=key_path or None,
        remote_dir=remote_dir,
        ssh_user=ssh_user or None,
    )


@task(positional=["nodes"])
def create(ctx, nodes=1, settings=""):
    """Create AWS benchmark nodes and wait until they pass status checks."""
    _run_or_exit(create_instances, nodes=int(nodes), settings_file=settings or None)


@task
def info(ctx, settings=""):
    """Display existing AWS benchmark nodes."""
    _run_or_exit(print_info, settings_file=settings or None)


@task
def start(ctx, max=100, settings=""):
    """Start stopped AWS benchmark nodes."""
    _run_or_exit(start_instances, max_per_region=int(max), settings_file=settings or None)


@task
def stop(ctx, settings=""):
    """Stop running AWS benchmark nodes."""
    _run_or_exit(stop_instances, settings_file=settings or None)


@task
def destroy(ctx, settings=""):
    """Terminate AWS benchmark nodes."""
    _run_or_exit(destroy_instances, settings_file=settings or None)


@task
def logs(ctx, run=""):
    """Print a compact summary for a benchmark run directory."""
    print_latest_summary(run or None)
