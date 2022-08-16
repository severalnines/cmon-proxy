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
	"errors"
	"testing"
	"time"
)

func TestDo(t *testing.T) {
	type args struct {
		cmd     Command
		cleaner Cleaner
		count   int
		wait    time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"ok",
			args{
				func(_ int) error {
					return nil
				},
				nil,
				1,
				0,
			},
			false,
		},
		{
			"fail",
			args{
				func(_ int) error {
					return errors.New("fail")
				},
				nil,
				3,
				0,
			},
			true,
		},
		{
			"ok cleaner",
			args{
				func(_ int) error {
					return nil
				},
				func(_ error, _ int) error {
					return nil
				},
				1,
				0,
			},
			false,
		},
		{
			"ok second attempt",
			args{
				func(i int) error {
					if i == 0 {
						return errors.New("first fail")
					}
					return nil
				},
				func(_ error, _ int) error {
					return nil
				},
				2,
				0,
			},
			false,
		},
		{
			"ok third attempt",
			args{
				func(i int) error {
					if i < 2 {
						return errors.New("first fail")
					}
					return nil
				},
				func(_ error, _ int) error {
					return nil
				},
				3,
				0,
			},
			false,
		},
		{
			"fail fourth attempt",
			args{
				func(i int) error {
					if i < 3 {
						return errors.New("first fail")
					}
					return nil
				},
				func(_ error, _ int) error {
					return nil
				},
				3,
				0,
			},
			true,
		},
		{
			"fail cmd",
			args{
				func(_ int) error {
					return errors.New("fail")
				},
				nil,
				1,
				0,
			},
			true,
		},
		{
			"fail cleaner",
			args{
				func(i int) error {
					return errors.New("fail cmd")
				},
				func(err error, _ int) error {
					return errors.New("fail cleaner")
				},
				2,
				0,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Do(tt.args.cmd, tt.args.cleaner, &Config{tt.args.count, tt.args.wait}); (err != nil) != tt.wantErr {
				t.Errorf("Do() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDo2(t *testing.T) {
	now := time.Now().Unix()
	if err := Do(func(i int) error {
		if i < 1 {
			return errors.New("fail")
		}
		return nil
	}, func(err error, i int) error {
		return nil
	}, &Config{2, time.Second * 3}); err != nil {
		t.Error(err)
	}
	if time.Now().Unix()-now != int64((time.Second * 3).Seconds()) {
		t.Error("wait failed")
	}
	if err := Do(func(i int) error {
		if i < 1 {
			return errors.New("fail")
		}
		return nil
	}, func(err error, i int) error {
		return nil
	}, &Config{3, time.Second * 3}); err != nil {
		t.Error(err)
	}
	if time.Now().Unix()-now != int64((time.Second * 6).Seconds()) {
		t.Error("wait failed")
	}
}
