#!/usr/bin/env python

import collections, json

# If something goes wrong while emailing account credentials to
# students, you can put a list of emails which did successfully get
# sent in a file named sent.txt and call this script to remove those
# passwords out of the database so they won't get resent.

if __name__ == '__main__':
    with open('sent.txt', 'rb') as f:
        sent = set([email.split('@')[0] for email in f.read().split()])
    with open('config/state.json', 'rb') as f:
        state = json.load(f, object_pairs_hook=collections.OrderedDict)
    for user in state['users'].itervalues():
        if user['username'] in sent and 'password' in user:
            del user['password']
    with open('config/state.json', 'wb') as f:
        json.dump(state, f)
