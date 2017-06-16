#!/bin/bash
echo "starting inotify listener on $(pwd)"
ts=$(date +%s)
# feed the inotify events into a while loop that creates
# the variables 'date' 'time' 'dir' 'file' and 'event'
inotifywait -mr --timefmt '%d/%m/%y %H:%M' --format '%T %w %f %e' \
-e modify $(pwd) \
| while read date time dir file event
do
    # only run the loop once every 5 seconds.
    cts=$(date +%s)
    if [ "$((cts - ts))" -gt 5 ]; then
        # execute compilation and tests
        if [[ "$file" =~ \.go$ && "$dir" =~ "$(pwd)" ]]; then
            echo --- $date $time ---
            [ ! -z "$(pidof autograph)" ] && killall autograph
            make all
            echo
            # move timestamp forward
            ts=$cts
        fi
    fi
done
