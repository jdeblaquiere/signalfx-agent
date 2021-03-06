<!--- GENERATED BY gomplate from scripts/docs/monitor-page.md.tmpl --->

# dotnet

(Windows Only) This monitor reports metrics for .NET applications.

The most critical .NET performance counters
* exceptions
* logical threads
* physical threads
* heap bytes
* time in GC
* committed bytes
* pinned objects

## Windows Performance Counters
The underlying source for these metrics are Windows Performance Counters.
Most of the performance counters that we query in this monitor are actually Gauges
that represent rates per second and percentages.

This monitor reports the instantaneous values for these Windows Performance Counters.
This means that in between a collection interval, spikes could occur on the
Performance Counters.  The best way to mitigate this limitation is to increase
the reporting interval on this monitor to collect more frequently.

Sample YAML configuration:

```yaml
monitors:
 - type: dotnet
```


Monitor Type: `dotnet`

[Monitor Source Code](https://github.com/signalfx/signalfx-agent/tree/master/internal/monitors/dotnet)

**Accepts Endpoints**: No

**Multiple Instances Allowed**: **No**

## Configuration

| Config option | Required | Type | Description |
| --- | --- | --- | --- |
| `counterRefreshInterval` | no | `int64` | (Windows Only) Number of seconds that wildcards in counter paths should be expanded and how often to refresh counters from configuration. (**default:** `60s`) |
| `printValid` | no | `bool` | (Windows Only) Print out the configurations that match available performance counters.  This used for debugging. (**default:** `false`) |




## Metrics

The following table lists the metrics available for this monitor. Metrics that are not marked as Custom are standard metrics and are monitored by default.

| Name | Type | Custom | Description |
| ---  | ---  | ---    | ---         |
| `net_clr_exceptions.num_exceps_thrown_sec` | gauge | X | The number of exceptions thrown by .NET applications. |
| `net_clr_locksandthreads.contention_rate_sec` | gauge | X | The rate of thread of thread contention per second for .NET applications. |
| `net_clr_locksandthreads.current_queue_length` | gauge | X | The current thread queue length for .NET applications. |
| `net_clr_locksandthreads.num_of_current_logical_threads` | gauge | X | The number of current logical threads for .NET applications. |
| `net_clr_locksandthreads.num_of_current_physical_threads` | gauge | X | The number of current physical threads for .NET applications. |
| `net_clr_memory.num_bytes_in_all_heaps` | gauge | X | The number of bytes in all heaps for .NET applications. |
| `net_clr_memory.num_gc_handles` | gauge | X | The number of garbage collection handles held by .NET applications. |
| `net_clr_memory.num_of_pinned_objects` | gauge | X | The number of objects pinned in memory by .NET applications. |
| `net_clr_memory.num_total_committed_bytes` | gauge | X | The total number of bytes committed to memory by .NET applications. |
| `net_clr_memory.num_total_reserved_bytes` | gauge | X | The total number of bytes reserved by .NET applications. |
| `net_clr_memory.pct_time_in_gc` | gauge | X | The percentage of time spent garbage collecting by .NET applications. |


To specify custom metrics you want to monitor, add a `metricsToInclude` filter
to the agent configuration, as shown in the code snippet below. The snippet
lists all available custom metrics. You can copy and paste the snippet into
your configuration file, then delete any custom metrics that you do not want
sent.

Note that some of the custom metrics require you to set a flag as well as add
them to the list. Check the monitor configuration file to see if a flag is
required for gathering additional metrics.

```yaml

metricsToInclude:
  - metricNames:
    - net_clr_exceptions.num_exceps_thrown_sec
    - net_clr_locksandthreads.contention_rate_sec
    - net_clr_locksandthreads.current_queue_length
    - net_clr_locksandthreads.num_of_current_logical_threads
    - net_clr_locksandthreads.num_of_current_physical_threads
    - net_clr_memory.num_bytes_in_all_heaps
    - net_clr_memory.num_gc_handles
    - net_clr_memory.num_of_pinned_objects
    - net_clr_memory.num_total_committed_bytes
    - net_clr_memory.num_total_reserved_bytes
    - net_clr_memory.pct_time_in_gc
    monitorType: dotnet
```




