#!/usr/bin/env python

import os, subprocess

def monitor(queue):
    root_dir = os.path.dirname(os.path.realpath(__file__))
    log_filename = os.path.join(root_dir, '%s_queue.log' % queue)

    if not os.path.exists(log_filename):
        header = subprocess.check_output(['qstat', '-Q', queue]).split('\n')[:2]
        #                    YYYY-MM-DD HH:MM:SS
        header = '\n'.join(['                    %s' % line for line in header])
        with open(log_filename, 'wb') as f:
            f.write('%s\n' % header)

    date = subprocess.check_output(['date', '+%Y-%m-%d %H:%M:%S']).strip()
    status = subprocess.check_output(['qstat', '-Q', queue]).split('\n')[2]

    with open(log_filename, 'ab') as f:
        f.write('%s %s\n' % (date, status))

    subprocess.check_call(['uniq', '--skip-fields', '2', log_filename, '%s.new' % log_filename])
    os.rename('%s.new' % log_filename, log_filename)

if __name__ == '__main__':
    monitor('batch')
