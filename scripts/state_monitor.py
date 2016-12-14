#!/usr/bin/env python

import collections, json, os, subprocess

###
### Parsing qsub -f
###

def parse_attribute(attribute, is_first):
    attribute = ''.join(attribute)
    if is_first:
        key, value = attribute.split(': ', 1)
        return (key.lower().replace(' ', '_'), value)
    key, value = attribute.split(' = ', 1)
    return (key.lower().replace(' ', '_'), value)

def parse_status(logs):
    entries = [entry for entry in logs.split('\n\n') if len(entry.strip()) > 0]
    jobs = []
    for entry in entries:
        lines = entry.split('\n')
        job = []
        attribute = None
        is_first = True
        for line in lines:
            if line.startswith('\t'):
                attribute.append(line.strip())
            else:
                if attribute is not None:
                    job.append(parse_attribute(attribute, is_first))
                    is_first = False
                attribute = [line.strip()]
        job.append(parse_attribute(attribute, is_first))
        jobs.append(collections.OrderedDict(job))
    return jobs

###
### Parsing internal JSON state
###

def load_state(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, 'rb') as f:
        return json.load(f, object_pairs_hook=collections.OrderedDict)

def dump_state(state, filename):
    with open(filename, 'wb') as f:
        return json.dump(state, f, indent = 2)

###
### State
###

def merge_state(new_state, old_state):
    new_state_dict = collections.OrderedDict([(state['job_id'], state) for state in new_state])
    state_dict = collections.OrderedDict([(state['job_id'], state) for state in old_state])
    state_dict.update(new_state_dict)
    return list(state_dict.itervalues())

if __name__ == '__main__':
    root_dir = os.path.dirname(os.path.realpath(__file__))
    state_filename = os.path.join(root_dir, 'all_state.json')

    new_state = parse_status(subprocess.check_output(['sudo', 'qstat', '-f']))
    old_state = load_state(state_filename)
    state = merge_state(new_state, old_state)
    dump_state(state, state_filename)
