// hooks the syscall entry/exit tracepoints and nothing deeper. this monitor is near-perfect on the plain-syscall path and
// goes blind on the io_uring paths — because io_uring reads/writes never pass through these syscall tracepoints at all.

