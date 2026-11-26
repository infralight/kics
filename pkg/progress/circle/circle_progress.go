package circle

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Checkmarx/kics/v2/internal/constants"
	"github.com/cheggaaa/pb/v3"
)

const (
	barWidth     = 0
	sleepTimeout = 100
)

// ProgressBar is a struct that holds the required fields for
// a Circle Progress Bar
type ProgressBar struct {
	label string
	pBar  *pb.ProgressBar
	close func() error
	done  chan struct{}
}

// NewProgressBar creates a new instance of a Circle Progress Bar
func NewProgressBar(label string, silent bool) ProgressBar {
	newPb := pb.New64(constants.MaxInteger)
	tmp := fmt.Sprintf(`{{ %q }} {{(cycle . "\\" "-" "|" "/" "-" "|" )}}`, label)
	newPb.SetWidth(barWidth)
	newPb.SetTemplateString(tmp)
	if silent {
		newPb.SetWriter(io.Discard)
	}
	newPb.Start()

	done := make(chan struct{})
	var once sync.Once
	return ProgressBar{
		label: label,
		pBar:  newPb,
		done:  done,
		close: func() error {
			once.Do(func() { close(done) })
			newPb.Finish()
			return nil
		},
	}
}

// Start initializes the Circle Progress Bar
func (p ProgressBar) Start() {
	for { // increment until the Close func is called
		p.pBar.Increment()
		select {
		case <-p.done: // without this a long-lived process keeps one goroutine per bar forever
			return
		case <-time.After(time.Millisecond * sleepTimeout): // lower cpu usage from infinite loop
		}
	}
}

// Close stops the Circle Progress Bar and
// changes the template to done
func (p ProgressBar) Close() error {
	p.pBar.SetTemplateString(fmt.Sprintf("%sDone", p.label))
	return p.close()
}
