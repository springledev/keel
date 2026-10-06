package dockerhost

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/springledev/keel/runner"
)

func TestPickComposeFiles(t *testing.T) {
	tests := []struct {
		name    string
		present []string
		want    []string
	}{
		{"none", []string{"README.md"}, nil},
		{"compose.yaml", []string{"compose.yaml"}, []string{"compose.yaml"}},
		{"lookup order prefers compose.yaml", []string{"docker-compose.yml", "compose.yml", "compose.yaml"}, []string{"compose.yaml"}},
		{"yml before docker-compose", []string{"docker-compose.yaml", "compose.yml"}, []string{"compose.yml"}},
		{"legacy v1", []string{"docker-compose.yml"}, []string{"docker-compose.yml"}},
		{"overrides in order", []string{"compose.override.yml", "compose.override.yaml", "compose.yaml"}, []string{"compose.yaml", "compose.override.yaml", "compose.override.yml"}},
		{"docker-compose override", []string{"docker-compose.yml", "docker-compose.override.yml"}, []string{"docker-compose.yml", "docker-compose.override.yml"}},
		{"override alone is not a stack", []string{"compose.override.yaml"}, nil},
		{"override of other family ignored", []string{"compose.yaml", "docker-compose.override.yml"}, []string{"compose.yaml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PickComposeFiles(tt.present); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PickComposeFiles(%v) = %v, want %v", tt.present, got, tt.want)
			}
		})
	}
}

func TestMergeComposeProjects(t *testing.T) {
	labelled := []ComposeProject{{Name: "immich", WorkingDir: "/opt/immich", Source: ComposeSourceLabels}}
	registered := []ComposeProject{{Name: "x", WorkingDir: "/opt/immich", Source: ComposeSourceRegistered}, {Name: "blog", WorkingDir: "/srv/blog", Source: ComposeSourceRegistered}}
	scanned := []ComposeProject{{Name: "blog", WorkingDir: "/srv/blog2", Source: ComposeSourceScan}, {Name: "wiki", WorkingDir: "/srv/wiki", Source: ComposeSourceScan}}
	got := MergeComposeProjects(labelled, registered, scanned)
	var names []string
	for _, p := range got {
		names = append(names, p.Name+":"+p.Source)
	}
	want := []string{"blog:registered", "immich:labels", "wiki:scan"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("MergeComposeProjects = %v, want %v", names, want)
	}
}

func TestScanComposeDirs(t *testing.T) {
	script := `case "$*" in
*"-v /srv/stacks:/data:ro"*)
  printf '%s\n' './README' 'blog/compose.yml' 'blog/compose.override.yml' 'blog/docker-compose.yml' 'wiki/docker-compose.yaml' 'empty/compose.override.yaml';;
esac
exit 0
`
	d := stubDocker(t, script)
	got, err := ScanComposeDirs(context.Background(), &runner.Runner{}, d, "alpine:3.20", []string{"/srv/stacks"}, true, ComposeSourceScan)
	if err != nil {
		t.Fatalf("ScanComposeDirs error: %v", err)
	}
	want := []ComposeProject{
		{Name: "blog", WorkingDir: "/srv/stacks/blog", Source: "scan", ConfigFiles: []string{"/srv/stacks/blog/compose.yml", "/srv/stacks/blog/compose.override.yml"}},
		{Name: "wiki", WorkingDir: "/srv/stacks/wiki", Source: "scan", ConfigFiles: []string{"/srv/stacks/wiki/docker-compose.yaml"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ScanComposeDirs = %+v, want %+v", got, want)
	}
}

func TestScanComposeDirsFailureHasContext(t *testing.T) {
	d := stubDocker(t, "echo boom >&2; exit 1\n")
	_, err := ScanComposeDirs(context.Background(), &runner.Runner{}, d, "alpine", []string{"/nope"}, false, ComposeSourceRegistered)
	if err == nil || !strings.Contains(err.Error(), "/nope") {
		t.Errorf("error = %v, want it to name the folder", err)
	}
}

func TestListComposeProjectsCustomFiles(t *testing.T) {
	script := `printf '%s\n' '{"Names":"x_web","Image":"nginx","Labels":"com.docker.compose.project=shop,com.docker.compose.service=web,com.docker.compose.project.working_dir=/home/me,com.docker.compose.project.config_files=/etc/stacks/x/stack.yaml,/etc/stacks/x/extra.yml"}'
exit 0
`
	d := stubDocker(t, script)
	got, err := ListComposeProjects(context.Background(), &runner.Runner{}, d)
	if err != nil || len(got) != 1 {
		t.Fatalf("ListComposeProjects = %+v, %v; want one project", got, err)
	}
	p := got[0]
	wantFiles := []string{"/etc/stacks/x/stack.yaml", "/etc/stacks/x/extra.yml"}
	if p.Name != "shop" || p.WorkingDir != "/home/me" || !reflect.DeepEqual(p.ConfigFiles, wantFiles) || p.Source != ComposeSourceLabels {
		t.Errorf("project = %+v, want label name, working_dir and -f files in order", p)
	}
}
