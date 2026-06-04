import os
from contextlib import contextmanager

from fabric import task

from tychebench.results import print_latest_summary
from tychebench.errors import BenchError
from tychebench.runner import organize_existing_runs, run_aws, run_local
from tychebench.aws import (
    create_instances,
    destroy_instances,
    print_info,
    start_instances,
    stop_instances,
)


DEFAULT_PROTOCOLS = "tyche,tyche-scrape,tyche-reconfig,tyche-scrape-reconfig,asyrand,grandline,spurt"


@contextmanager
def _temporary_env(**values):
    previous = {}
    for key, value in values.items():
        if value is None or str(value).strip() == "":
            continue
        previous[key] = os.environ.get(key)
        os.environ[key] = str(value)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


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
    protocols=DEFAULT_PROTOCOLS,
    out="",
    fault_threshold="",
    reconfig_events="",
    reconfig_min_n="",
    reconfig_max_n="",
    reconfig_seed="",
    reconfig_queue_len="",
):
    """Run the local in-memory beacon benchmark."""
    with _temporary_env(
        TYCHE_RECONFIG_EVENTS=reconfig_events,
        TYCHE_RECONFIG_MIN_N=reconfig_min_n,
        TYCHE_RECONFIG_MAX_N=reconfig_max_n,
        TYCHE_RECONFIG_SEED=reconfig_seed,
        TYCHE_RECONFIG_QUEUE_LEN=reconfig_queue_len,
    ):
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
    protocols=DEFAULT_PROTOCOLS,
    out="",
    key_path="",
    remote_dir="TycheBench",
    ssh_user="",
    reconfig_events="",
    reconfig_min_n="",
    reconfig_max_n="",
    reconfig_seed="",
    reconfig_queue_len="",
):
    """Run the AWS TCP beacon benchmark."""
    with _temporary_env(
        TYCHE_RECONFIG_EVENTS=reconfig_events,
        TYCHE_RECONFIG_MIN_N=reconfig_min_n,
        TYCHE_RECONFIG_MAX_N=reconfig_max_n,
        TYCHE_RECONFIG_SEED=reconfig_seed,
        TYCHE_RECONFIG_QUEUE_LEN=reconfig_queue_len,
    ):
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


@task(name="organize-runs")
def organize_runs(ctx):
    """Organize legacy timestamped run directories into stable config directories."""
    _run_or_exit(organize_existing_runs)
