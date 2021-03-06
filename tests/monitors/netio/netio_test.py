from functools import partial as p

import pytest

from tests.helpers.assertions import has_any_metric_or_dim, has_log_message
from tests.helpers.util import (
    ensure_never,
    get_monitor_dims_from_selfdescribe,
    get_monitor_metrics_from_selfdescribe,
    run_agent,
    wait_for,
)

pytestmark = [pytest.mark.windows, pytest.mark.netio, pytest.mark.monitor_without_endpoints]


def test_netio():
    expected_metrics = get_monitor_metrics_from_selfdescribe("net-io")
    expected_dims = get_monitor_dims_from_selfdescribe("net-io")
    with run_agent(
        """
    monitors:
      - type: net-io
    """
    ) as [backend, get_output, _]:
        assert wait_for(
            p(has_any_metric_or_dim, backend, expected_metrics, expected_dims), timeout_seconds=60
        ), "timed out waiting for metrics and/or dimensions!"
        assert not has_log_message(get_output().lower(), "error"), "error found in agent output!"


def test_netio_filter():
    expected_metrics = get_monitor_metrics_from_selfdescribe("net-io")
    try:
        expected_metrics.remove("network.total")
    except KeyError:
        pass

    with run_agent(
        """
    procPath: /proc
    monitors:
      - type: net-io
        interfaces:
         - "!*"
    """
    ) as [backend, get_output, _]:
        assert wait_for(
            p(has_any_metric_or_dim, backend, ["network.total"], []), timeout_seconds=60
        ), "timed out waiting for metrics and/or dimensions!"
        assert ensure_never(lambda: has_any_metric_or_dim(backend, expected_metrics, []))
        assert not has_log_message(get_output().lower(), "error"), "error found in agent output!"
