package main

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/go-kit/log/level"
	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/o11ydev/oy-toolkit/util/client"
	"github.com/o11ydev/oy-toolkit/util/cmd"
	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/promql/parser"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	//go:embed alerts.html.tmpl
	tmpl       string
	outputFile = kingpin.Flag(
		"output.file",
		"HTML output file",
	).Default("alerts.html").String()
)

type Alert struct {
	Name  string
	State string
}

type Node struct {
	Job      string
	Instance string
}

type result struct {
	UnattachedAlerts []Alert
	Nodes            []Node
}

func main() {
	c := client.InitCliFlags()
	logger := cmd.InitCmd("oy-alerts-dashboard")

	promClient, err := client.NewClient(c)
	if err != nil {
		level.Error(logger).Log("msg", "Can't create Prometheus client", "err", err)
		os.Exit(1)
	}

	pw := progress.NewWriter()
	pw.ShowETA(false)
	pw.ShowValue(false)
	pw.ShowPercentage(false)
	pw.ShowTime(false)
	go pw.Render()

	var output result

	fetchData(pw, promClient, &output)
	pw.Stop()

	for pw.IsRenderInProgress() {
		time.Sleep(time.Millisecond * 100)
	}
}

func fetchData(pw progress.Writer, client api.Client, output *result) {
	t1 := &progress.Tracker{
		Message: "Fetching instances",
	}
	t2 := &progress.Tracker{
		Message: "Fetching alerts",
	}
	pw.AppendTracker(t1)
	pw.AppendTracker(t2)

	v1api := v1.NewAPI(client)

	nodes := make(map[Node][]Alert, 0)

	//{
	//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	//	defer cancel()
	//	tgs, err := v1api.Targets(ctx)
	//	if err != nil {
	//		fmt.Printf("Error querying Prometheus: %v\n", err)
	//		t1.MarkAsErrored()
	//		return
	//	}

	//	for _, t := range tgs.Active {
	//		nodes[Node{Job: string(t.Labels["job"]), Instance: string(t.Labels["instance"])}] = make([]Alert, 0)
	//	}

	//	t1.MarkAsDone()

	//}

	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rules, err := v1api.Rules(ctx)
		if err != nil {
			fmt.Printf("Error querying Prometheus: %v\n", err)
			t2.MarkAsErrored()
			return
		}
		t2.MarkAsDone()

		todo := make([]v1.AlertingRule, 0)
		for _, g := range rules.Groups {
			for _, rule := range g.Rules {
				switch v := rule.(type) {
				case v1.AlertingRule:
					todo = append(todo, v)
				default:
					continue
				}
			}
		}
		t3 := &progress.Tracker{
			Message: "Analyzing alerts",
			Total:   int64(len(todo)),
		}
		pw.AppendTracker(t3)

		for _, r := range todo {
			for _, a := range r.Alerts {
				if _, ok := nodes[Node{Job: string(a.Labels["job"]), Instance: string(a.Labels["instance"])}]; !ok {
					nodes[Node{Job: string(a.Labels["job"]), Instance: string(a.Labels["instance"])}] = make([]Alert, 0)
				}
				x := nodes[Node{Job: string(a.Labels["job"]), Instance: string(a.Labels["instance"])}]
				nodes[Node{Job: string(a.Labels["job"]), Instance: string(a.Labels["instance"])}] = append(x, Alert{Name: r.Name, State: string(a.State)})
			}

			out, err := analyzeMetricsFromQuery(r.Query)
			if err != nil {
				fmt.Printf("%s\n", err.Error())
				t3.IncrementWithError(1)
				continue
			}
			if len(out) == 0 {
				t3.Increment(1)
				continue
			}

			query := ""
			for i, v := range out {
				if i > 0 {
					query = query + " and "
				}
				query = query + "group by (instance,job) (" + v + ")"
			}
			res, _, err := v1api.Query(ctx, query, time.Now())
			if err != nil {
				fmt.Printf("%s\n", err.Error())
				t3.IncrementWithError(1)
				continue
			}
			mat := res.(model.Vector)
			for _, m := range mat {
				x, ok := nodes[Node{Job: string(m.Metric["job"]), Instance: string(m.Metric["instance"])}]
				if !ok {
					x = make([]Alert, 0)
				}
				nodes[Node{Job: string(m.Metric["job"]), Instance: string(m.Metric["instance"])}] = append(x, Alert{Name: r.Name, State: "present"})
			}
			t3.Increment(1)
		}

	}

	var data = make(map[string]map[string][]Alert, 0)

	for nodeInfo, alerts := range nodes {
		if _, ok := data[nodeInfo.Instance]; !ok {
			data[nodeInfo.Instance] = make(map[string][]Alert, 0)
		}
		if _, ok := data[nodeInfo.Instance][nodeInfo.Job]; !ok {
			data[nodeInfo.Instance][nodeInfo.Job] = make([]Alert, 0)
		}
		for _, a := range alerts {
			if a.State == "present" {
				continue
			}
			data[nodeInfo.Instance][nodeInfo.Job] = append(data[nodeInfo.Instance][nodeInfo.Job], a)
		}
		for _, a := range alerts {
			var found bool
			if a.State != "present" {
				continue
			}
			for _, existingA := range data[nodeInfo.Instance][nodeInfo.Job] {
				if existingA.Name == a.Name {
					found = true
					continue
				}
			}
			if found {
				continue
			}
			data[nodeInfo.Instance][nodeInfo.Job] = append(data[nodeInfo.Instance][nodeInfo.Job], a)
		}
	}

	t, err := template.New("").Parse(tmpl)
	if err != nil {
		fmt.Printf("error: %s", err.Error())
		os.Exit(1)
	}
	f, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("error: %s", err.Error())
		os.Exit(1)
	}
	err = t.Execute(f, data)
	if err != nil {
		fmt.Printf("error: %s", err.Error())
		os.Exit(1)
	}
}

func analyzeMetricsFromQuery(query string) ([]string, error) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return nil, err
	}
	return extractMetricFromExpr(expr)
}

func extractMetricFromExpr(exp parser.Expr) ([]string, error) {
	switch x := exp.(type) {
	case *parser.BinaryExpr:
		l, err := extractMetricFromExpr(x.LHS)
		if err != nil {
			return nil, err
		}
		r, err := extractMetricFromExpr(x.RHS)
		if err != nil {
			return nil, err
		}
		return append(l, r...), nil
	case *parser.AggregateExpr:
		return extractMetricFromExpr(x.Expr)
	case *parser.SubqueryExpr:
		return extractMetricFromExpr(x.Expr)
	case *parser.ParenExpr:
		return extractMetricFromExpr(x.Expr)
	case *parser.NumberLiteral, *parser.StringLiteral:
		return nil, nil
	case *parser.StepInvariantExpr:
		return extractMetricFromExpr(x.Expr)
	case *parser.UnaryExpr:
		return extractMetricFromExpr(x.Expr)
	case *parser.VectorSelector:
		return []string{x.String()}, nil
	case *parser.MatrixSelector:
		return []string{x.VectorSelector.String()}, nil
	case *parser.Call:
		m := make([]string, 0)
		for _, a := range x.Args {
			r, err := extractMetricFromExpr(a)
			if err != nil {
				return nil, err
			}
			m = append(m, r...)
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unkown expr: %v", x)
	}
}
