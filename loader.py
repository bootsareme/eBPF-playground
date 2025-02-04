from bcc import BPF
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} '<BPF program>'")
    sys.exit(1)

bpf_program = sys.argv[1]

try:
    b = BPF(text=bpf_program)
    print("BPF program loaded successfully.")
    b.trace_print()
except Exception as e:
    print(f"Error loading BPF program: {e}")
    sys.exit(1)
