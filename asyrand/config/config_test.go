package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDeploymentTemplatesAndDerivedParameters(t *testing.T) {
	for _, path := range []string{"../configs/local_4.json", "../configs/local_8.json", "../configs/local_8_rounds_1000.json", "../configs/aws_8.json"} {
		c, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if c.Quorum() != len(c.Members())-c.F || c.Threshold() != c.F+1 || c.RSQCapacity() != c.F+1 {
			t.Fatal("invalid derived parameters")
		}
		if !c.ParallelConsumption {
			t.Fatal("deployment template does not enable parallel consumption")
		}
		bad := c
		bad.ProductionWindow = 1
		if bad.Validate() == nil {
			t.Fatal("accepted W<2")
		}
		bad = c
		bad.AdaptiveProduction = true
		bad.ProductionWindowMin = 1
		if bad.Validate() == nil {
			t.Fatal("adaptive window allowed W<2")
		}
		bad.ProductionWindowMin = bad.ProductionWindow + 1
		if bad.Validate() == nil {
			t.Fatal("adaptive minimum exceeds peer-message horizon")
		}
		bad = c
		bad.F = len(c.Members())/3 + 1
		if bad.Validate() == nil {
			t.Fatal("accepted invalid fault bound")
		}
	}
}

func TestParallelDefaultPreservesExplicitFalse(t *testing.T) {
	data, err := os.ReadFile("../configs/local_4.json")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	for _, flag := range []string{"omitted", "true", "false"} {
		delete(fields, "parallel_consumption")
		if flag != "omitted" {
			fields["parallel_consumption"] = flag == "true"
		}
		encoded, _ := json.Marshal(fields)
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil || c.ParallelConsumption != (flag != "false") {
			t.Fatalf("flag %s: parallel=%t, err=%v", flag, c.ParallelConsumption, err)
		}
	}
}
