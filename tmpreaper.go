package main

import (
	"os"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"
)

type tmpreaper struct {
	ticker *time.Ticker
	exit   chan interface{}
}

func (r *tmpreaper) schedule(duration time.Duration) {
	if duration.Seconds() <= 0 {
		log.Warn("tmpreaper/schedule: No duration provided, not scheduling")
		return
	}

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

func (r *tmpreaper) cleanTmp() {
	// Remove temp files that have not been accessed in the last 15 minutes
	cmd := exec.Command("tmpreaper", "--protect", "'/tmp/autograph_gpg2_*'", "--showdeleted", "15m", os.TempDir())
	out, err := cmd.CombinedOutput()
	log.Debugf("tmpreaper/cleanTmp: output: %s", out)
	if err != nil {
		log.Errorf("tmpreaper/cleanTmp: error: %s", err)
	}
}

func newTmpReaper(ag *autographer, duration time.Duration) *tmpreaper {
	r := new(tmpreaper)
	r.exit = ag.exit
	go r.schedule(duration)
	return r
}
