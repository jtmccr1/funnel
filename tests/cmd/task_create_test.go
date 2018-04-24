package cmd

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"

	taskCmd "github.com/ohsu-comp-bio/funnel/cmd/task"
	"github.com/ohsu-comp-bio/funnel/tests"
)

func TestCreateStdin(t *testing.T) {
	conf := tests.DefaultConfig()
	conf.Compute = "noop"
	fun := tests.NewFunnel(conf)
	fun.StartServer()

	a, _ := ioutil.ReadFile("hello-world.json")
	b, _ := ioutil.ReadFile("hello-world.json")

	in := &bytes.Buffer{}
	out := &bytes.Buffer{}
	in.Write(a)
	in.Write(b)

	err := taskCmd.Create(conf.Server.HTTPAddress(), []string{"hello-world.json"}, in, out)
	if err != nil {
		t.Fatal(err)
	}

	ids := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(ids) != 3 {
		t.Fatal("err", ids)
	}
}
