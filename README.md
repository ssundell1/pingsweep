# pingsweep

usage: pingsweep.py [-h] -n N [N ...] [-v] [-o [file]] [-t [seconds]]

Sweeps one or more networks for active hosts

optional arguments:
  -h, --help    show this help message and exit
  -n N [N ...]  networks to scan separated by comma, e.g. 192.168.0.0/24,192.168.1.0/24
  -v            verbosity level, max -vvv
  -o [file]
  -t [seconds]  ping timeout

examples:
        pingsweep.py -n 192.168.0.0/24
        pingsweep.py -n 192.168.1.0/24,10.0.0.0/16
        pingsweep.py -n 192.168.1.0/24,10.0.0.0/16 -v -o pingsweep.txt
