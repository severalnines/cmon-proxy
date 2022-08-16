package retry
// Copyright 2022 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.


import (
	"strconv"
	"time"

	"github.com/pkg/errors"
)

// Do will retry cmd for count times. cleaner will be executed
// if cmd returned an error.
func Do(cmd Command, cleaner Cleaner, cnf *Config, label ...string) error {
	msg := ""
	if len(label) > 0 {
		msg = label[0] + ": "
	}
	var lastErr error
	for i := 0; i < cnf.Count; i++ {
		if err := cmd(i); err != nil {
			lastErr = err
			if cleaner != nil {
				if cErr := cleaner(err, i); cErr != nil {
					return errors.Wrap(
						cErr,
						msg+"original err: "+err.Error()+"failed to clean between retries",
					)
				}
			}
			if cnf.Wait > 0 {
				time.Sleep(cnf.Wait)
			}
			continue
		} else {
			return nil
		}
	}
	if lastErr != nil {
		return errors.Wrap(lastErr, msg+"command failed after "+strconv.Itoa(cnf.Count)+" retries")
	}
	return errors.Errorf(msg+"command failed after %d retries", cnf.Count)
}

// Command func to execute.
type Command func(int) error

// Cleaner func is executed between if a Command failed with error.
type Cleaner func(error, int) error

// Config of the retry action.
type Config struct {
	// Count is the number of times to retry.
	Count int

	// Wait is the wait time between retries.
	Wait time.Duration
}

func (c *Config) Seconds() int {
	return int((time.Duration(c.Count) * c.Wait).Seconds())
}

// EmptyCleaner is a Cleaner that always returns nil.
func EmptyCleaner(_ error, _ int) error { return nil }
