#!/usr/bin/env python

import collections, json

# This script deletes all the password entries for users. This has the
# side effect of preventing emails from being sent to any of those
# users.

if __name__ == '__main__':
    with open('config/state.json', 'rb') as f:
        state = json.load(f, object_pairs_hook=collections.OrderedDict)
    for user in state['users'].itervalues():
        if 'password' in user:
            del user['password']
    with open('config/state.json', 'wb') as f:
        json.dump(state, f)
