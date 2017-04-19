#!/bin/bash
echo "starting inotify listener on $(pwd)"
# feed the inotify events into a while loop that creates
# the variables 'date' 'time' 'dir' 'file' and 'event'
inotifywait -mr --timefmt '%d/%m/%y %H:%M' --format '%T %w %f %e' \
-e modify $(pwd) \
| while read date time dir file event
do
    if [[ "$file" =~ \.go$ && "$dir" =~ "$(pwd)" ]]; then
        echo --- $date $time ---
        [ ! -z "$(pidof autograph)" ] && killall autograph
        make install && make test
        echo
    fi
    if [[ "$file" == autograph.yaml && "$dir" =~ "$(pwd)" ]]; then
        echo --- $date $time ---
        echo configuration changed, killing running autograph instance
	    killall autograph
        echo
    fi
done
