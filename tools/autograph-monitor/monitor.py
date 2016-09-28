#!/usr/bin/env python

import os, sys
import subprocess

def autograph_monitor(event, context):
    lambda_task_root = "."
    if 'LAMBDA_TASK_ROOT' in os.environ:
        lambda_task_root = os.environ['LAMBDA_TASK_ROOT']
    command = 'PATH="%s" LAMBDA_TASK_ROOT="%s" %s/autograph-monitor' % (os.environ['PATH'], lambda_task_root, lambda_task_root)
    print("Calling monitoring client using: %s" % (command))
    exit_code = subprocess.call([lambda_task_root + '/autograph-monitor'], env=os.environ.copy())
    if exit_code > 0:
        raise ValueError("Monitor failed! Check the logs for more information.")

if __name__ == '__main__':
    autograph_monitor(None, None)

