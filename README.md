## eBPF I/O Request Latency Monitor

This project is a homework assignment for EECS 6891 at Columbia University.

Environment: Debian 12

To run, execute:  `sudo ./iolatency [report period]`

To generate I/O request for testing purposes, use `fio` in a separate terminal. 
For example, run `fio --name=test --ioengine=posixaio --rw=randrw --bs=4m --numjobs=1 --size=1g --iodepth=16 --runtime=60 --time_based --end_fsync=1`

The program counts the number of I/O requests in each latency bucket, and outputs a histogram representing the distribution of I/O latencies.
Below is sample histogram (each star represents 10 I/O requests):
```
usecs           : count      | distribution
    0 -> 1      : 0          |                                                   |
    2 -> 3      : 0          |                                                   |
    4 -> 7      : 0          |                                                   |
    8 -> 15     : 0          |                                                   |
   16 -> 31     : 7          | *                                                 |
   32 -> 63     : 85         | *********                                         |
   64 -> 127    : 21         | ***                                               |
  128 -> 255    : 433        | ********************************************      |
  256 -> 511    : 331        | **********************************                |
  512 -> 1023   : 180        | *******************                               |
 1024 -> 2047   : 276        | ****************************                      |
 2048 -> 4095   : 256        | **************************                        |
 4096 -> 8191   : 40         | *****                                             |
 8192 -> 16383  : 0          |                                                   |
16384 -> 32767  : 0          |                                                   |
32768 -> 65535  : 0          |                                                   |
65536 -> 131071 : 0          |                                                   |
```
