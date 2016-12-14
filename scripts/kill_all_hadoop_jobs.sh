#!/bin/bash

hadoop job -list | tail --lines +3 | cut -f1 | xargs --no-run-if-empty --max-lines=1 --verbose hadoop job -kill || true
