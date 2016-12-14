#!/bin/bash

touch batch_jobs.log
sudo qstat | grep 'C batch' | cat batch_jobs.log - | sort -n | uniq > batch_jobs.log.new
mv batch_jobs.log.new batch_jobs.log
