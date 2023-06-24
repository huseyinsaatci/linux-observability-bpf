pid=$(eval "pidof ebpf_exporter_exe")
eval "psrecord $pid --interval 1 --duration 10 --plot benchmark_plot.png"