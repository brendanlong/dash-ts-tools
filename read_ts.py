#!/usr/bin/env python3
from ts import *
import sys

pmt_pid = None
pes_readers = {}
for ts_packet in read_ts(sys.argv[1]):
    print(ts_packet)
    if ts_packet.pid == ProgramAssociationTable.PID:
        pat = ProgramAssociationTable(ts_packet.payload)
        input()
        print(pat)
        programs = list(pat.programs.values())
        if len(programs) != 1:
            raise Exception("PAT has {} programs, but DASH only "
                            "allows 1 program."
                            .format(len(pat.programs)))
        if pmt_pid is not None and programs[0] != pmt_pid:
            raise Exception("PAT has new PMT PID. This program has "
                            "not been tested to handled this case.")
        pmt_pid = programs[0]

    elif ts_packet.pid == pmt_pid:
        input()
        pmt = ProgramMapTable(ts_packet.payload)
        print(pmt)
        for pid in pmt.streams:
            if pid not in pes_readers:
                pes_readers[pid] = PESReader()

    elif ts_packet.pid in pes_readers:
        pes_packet = pes_readers[ts_packet.pid].add_ts_packet(ts_packet)
        if pes_packet:
            input()
            print(pes_packet)
    input()
