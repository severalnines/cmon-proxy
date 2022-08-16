package api
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
	"encoding/json"
	"testing"
	"time"
)

func TestStatTS_MarshalJSON(t *testing.T) {
	var (
		ts  time.Time
		tj  []byte
		err error
	)
	ts, err = time.Parse(time.RFC3339, "2020-07-07T10:25:30Z")
	if err != nil {
		t.Fatal(ts)
	}
	tj, err = json.Marshal(StatTS(ts))
	if err != nil {
		t.Fatal(err)
	}
	if string(tj) != `"2020-07-07T10:25:30.000Z"` {
		t.Fatalf(`expected "2020-07-07T10:25:30.000Z", got "%s"`, string(tj))
	}
	ts, err = time.Parse(time.RFC3339, "1985-02-23T12:57:00.357Z")
	if err != nil {
		t.Fatal(ts)
	}
	tj, err = json.Marshal(StatTS(ts))
	if err != nil {
		t.Fatal(err)
	}
	if string(tj) != `"1985-02-23T12:57:00.357Z"` {
		t.Fatalf(`expected "1985-02-23T12:57:00.357Z", got "%s"`, string(tj))
	}
}
