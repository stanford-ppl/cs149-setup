#!/usr/bin/env python

import subprocess

if __name__ == '__main__':
    lines = subprocess.check_output(['pbsnodes']).split('\n')
    node = None
    state = None
    for line in lines:
        if not line.startswith(' '):
            if node is not None and state == 'free' or state == 'busy':
                subprocess.call(['ssh', '-q', node, 'true'])
            node = line.strip()
        else:
            elts = line.split()
            if elts[0] == 'state':
                state = elts[2]
