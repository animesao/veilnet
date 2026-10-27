name: Bug report
description: Report a problem with veilnet
labels: [bug]
body:
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: A clear description of the bug.
      placeholder: |
        Steps to reproduce, actual vs expected behavior.
    validations:
      required: true

  - type: input
    id: version
    attributes:
      label: veilctl version
      description: Output of `veilctl version`
      placeholder: veilctl 0.1.0
    validations:
      required: true

  - type: input
    id: kernel
    attributes:
      label: Kernel version
      description: Output of `uname -r`
    validations:
      required: true

  - type: textarea
    id: logs
    attributes:
      label: Relevant logs
      description: journalctl -u veilnet, dmesg, bpftool output
