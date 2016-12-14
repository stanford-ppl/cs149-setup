#!/usr/bin/env python

import datetime, json, numpy

def index_jobs(jobs, key):
    index = {}
    for job in jobs:
        if job[key] not in index:
            index[job[key]] = []
        index[job[key]].append(job)
    return index

def query_waits(jobs, key_queue_time, key_start_time, min_duration, interval_start, interval_end):
    result = []
    for job in jobs:
        if key_start_time in job:
            queue_time = datetime.datetime.strptime(job[key_queue_time], '%c')
            start_time = datetime.datetime.strptime(job[key_start_time], '%c')
            duration = (start_time - queue_time).total_seconds()
            if min_duration is not None and duration < min_duration:
                continue
            if interval_start is not None and interval_end is not None and (
                    queue_time < interval_start or interval_end < queue_time):
                continue
            result.append(duration)
    return result

if __name__ == '__main__':
    with open('all_state.json') as f:
        jobs = json.load(f)

    index = index_jobs(jobs, 'queue')
    for queue, queue_jobs in index.iteritems():
        print 'For queue "%s":' % queue

        now = datetime.datetime.now()
        intervals = [
            None,
            datetime.timedelta(weeks=1),
            datetime.timedelta(days=2),
            datetime.timedelta(days=1),
            datetime.timedelta(hours=6),
            datetime.timedelta(hours=1),
        ]
        for interval in intervals:
            print '  For interval "%s":' % interval

            interval_start = now - interval if interval is not None else None
            interval_end = now if interval is not None else None

            waits = query_waits(queue_jobs, 'qtime', 'start_time', None, interval_start, interval_end)
            nonzero_waits = query_waits(queue_jobs, 'qtime', 'start_time', 0.1, interval_start, interval_end)

            percent_nonzero_waits = 0.0
            if len(waits) > 0:
                percent_nonzero_waits = 100.0*len(nonzero_waits)/len(waits)

            print '    Number of jobs:         %d' % (
                len(waits))
            print '      Waits > 0.1 seconds:  %d (%.1f%%)' % (
                len(nonzero_waits),
                percent_nonzero_waits)
            print '    Mean wait time:         %.1f minutes' % (
                numpy.mean(waits)/60 if len(waits) > 0 else 0.0)
            print '      Waits > 0.1 seconds:  %.1f minutes' % (
                numpy.mean(nonzero_waits)/60 if len(nonzero_waits) > 0 else 0.0)
            print '    Percentiles: %6.1f (50th) %6.1f (75th) %6.1f (95th) %6.1f (max)' % (
                (numpy.percentile(waits, 50)/60 if len(waits) > 0 else 0.0),
                (numpy.percentile(waits, 75)/60 if len(waits) > 0 else 0.0),
                (numpy.percentile(waits, 95)/60 if len(waits) > 0 else 0.0),
                (max(waits)/60 if len(waits) > 0 else 0.0))
            print
