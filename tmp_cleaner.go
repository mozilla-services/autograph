package main

import (
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

type tmpCleaner struct {
	ticker *time.Ticker
	exit   chan interface{}
}

func (r *tmpCleaner) schedule(duration time.Duration) {
	if duration.Seconds() <= 0 {
		log.Warn("tmpcleaner/schedule: No duration provided, not scheduling")
		return
	}

	log.Debugf("tmpcleaner/schedule: Scheduling tmpcleaner to run every %s", duration.String())
	r.ticker = time.NewTicker(duration)

	for {
		select {
		case <-r.ticker.C:
			r.cleanTmp()
		case <-r.exit:
			return
		}
	}
}

func (r *tmpCleaner) cleanTmp() {
	minTime := time.Now().Add(time.Minute * -15)
	cleanFolder(os.TempDir(), minTime)
}

func cleanFolder(folder string, minTime time.Time) {
	// Remove temp files that have not been accessed in the last 15 minutes
	files, err := os.ReadDir(folder)
	if err != nil {
		log.Errorf("tmpcleaner/cleanFolder: Error reading from %s. %s", folder, err)
		return
	}

	for _, f := range files {
		if strings.Contains(f.Name(), "gpg2") {
			continue // Ignore gpg2 related files
		}
		fullPath := path.Join(folder, f.Name())
		if f.IsDir() {
			cleanFolder(fullPath, minTime)
			os.Remove(fullPath) // if folder is not empty this will fail silently, intentional
		} else {
			fs, err := f.Info()
			if err != nil {
				log.Warnf("tmpcleaner/cleanFolder: Error when retrieving stats for %s . %s", fullPath, err)
			}
			stat := fs.Sys().(*syscall.Stat_t)
			atime := time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec))

			if atime.Compare(minTime) < 0 {
				err := os.Remove(fullPath)
				size := fs.Size()
				if err != nil {
					log.Errorf("tmpcleaner/cleanFolder: Failed to remove %s . %s", fullPath, err)
				} else {
					log.Debugf("tmpcleaner/cleanFolder: Removed %s with %d bytes.", fullPath, size)
				}
			}
		}
	}
}

func newTmpCleaner(ag *autographer, duration time.Duration) *tmpCleaner {
	r := new(tmpCleaner)
	r.exit = ag.exit
	go r.schedule(duration)
	return r
}
