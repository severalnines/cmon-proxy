package api

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
