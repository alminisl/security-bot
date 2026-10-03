package collect

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/alminisl/security-bot/internal/model"
)

// dockerInspect mirrors the subset of `docker inspect` output the agents read.
type dockerInspect struct {
	Name  string `json:"Name"`
	State struct {
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Image  string `json:"Image"`
	Config struct {
		Image  string            `json:"Image"`
		User   string            `json:"User"`
		Env    []string          `json:"Env"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		NetworkMode    string   `json:"NetworkMode"`
		CapAdd         []string `json:"CapAdd"`
		SecurityOpt    []string `json:"SecurityOpt"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		Memory         int64    `json:"Memory"`
		PidMode        string   `json:"PidMode"`
		RestartPolicy  struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// Inventory gathers every running container in one docker call.
func Inventory(ctx context.Context, timeout time.Duration) ([]model.Container, error) {
	ids, err := sh(ctx, timeout, "docker", "ps", "-q")
	if err != nil {
		return nil, err
	}
	idList := lines(ids)
	if len(idList) == 0 {
		return nil, nil
	}
	args := append([]string{"inspect"}, idList...)
	raw, err := sh(ctx, timeout, "docker", args...)
	if err != nil {
		return nil, err
	}
	var insp []dockerInspect
	if err := json.Unmarshal([]byte(raw), &insp); err != nil {
		return nil, err
	}

	// Resolve image digests from the images themselves, keyed by image ID.
	// Matching on repository:tag misses anything pulled by digest, which
	// `docker images` does not list under a repo name at all.
	var imageIDs []string
	for _, in := range insp {
		if in.Image != "" {
			imageIDs = append(imageIDs, in.Image)
		}
	}
	digests := imageDigests(ctx, timeout, imageIDs)

	var out []model.Container
	for _, in := range insp {
		c := model.Container{
			Name:        strings.TrimPrefix(in.Name, "/"),
			Image:       model.ShortImage(in.Config.Image),
			Status:      in.State.Status,
			StartedAt:   in.State.StartedAt,
			Privileged:  in.HostConfig.Privileged,
			NetworkMode: in.HostConfig.NetworkMode,
			User:        in.Config.User,
			CapAdd:      in.HostConfig.CapAdd,
			SecurityOpt: in.HostConfig.SecurityOpt,
			ReadonlyFS:  in.HostConfig.ReadonlyRootfs,
			MemLimit:    in.HostConfig.Memory,
			RestartPol:  in.HostConfig.RestartPolicy.Name,
			Env:         in.Config.Env,
		}
		if in.State.Health != nil {
			c.Health = in.State.Health.Status
		}
		c.ImageDigest = digests[in.Image]
		// A reference pinned by digest carries it directly; prefer that, since
		// it is what the compose file actually asked for.
		if i := strings.Index(in.Config.Image, "@sha256:"); i > 0 {
			c.ImageDigest = in.Config.Image[i+1:]
		}
		c.Project = in.Config.Labels["com.docker.compose.project"]
		if c.Project == "" {
			c.Project = "standalone"
		}
		c.WorkingDir = in.Config.Labels["com.docker.compose.project.working_dir"]
		if v, ok := in.Config.Labels["com.centurylinklabs.watchtower.enable"]; ok {
			c.Watchtower = v == "true"
		}
		for _, k := range in.Config.Env {
			if i := strings.Index(k, "="); i > 0 {
				c.EnvKeys = append(c.EnvKeys, k[:i])
			}
		}
		for _, m := range in.Mounts {
			c.Mounts = append(c.Mounts, model.Mount{
				Type: m.Type, Source: m.Source, Destination: m.Destination, RW: m.RW,
			})
		}
		// A dual-stack publish shows up once for 0.0.0.0 and once for ::.
		// Collapse them: it is one mapping and one decision.
		seenBind := map[string]bool{}
		for cp, binds := range in.NetworkSettings.Ports {
			for _, b := range binds {
				ip := b.HostIP
				if ip == "::" || ip == "[::]" {
					ip = "0.0.0.0" // same exposure, canonical form
				}
				key := cp + "|" + ip + "|" + b.HostPort
				if seenBind[key] {
					continue
				}
				seenBind[key] = true
				c.Ports = append(c.Ports, model.Port{
					Container: cp, HostIP: ip, HostPort: b.HostPort,
				})
			}
		}
		sort.Slice(c.Ports, func(i, j int) bool { return c.Ports[i].HostPort < c.Ports[j].HostPort })
		out = append(out, c)
	}
	return out, nil
}

// imageDigests maps image ID -> repo digest, for the given image IDs. An image
// built locally has no repo digest and is simply absent from the result.
func imageDigests(ctx context.Context, timeout time.Duration, ids []string) map[string]string {
	out := map[string]string{}
	if len(ids) == 0 {
		return out
	}
	seen := map[string]bool{}
	var uniq []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}
	args := append([]string{"image", "inspect", "--format",
		"{{.Id}}\t{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}"}, uniq...)
	raw, err := sh(ctx, timeout, "docker", args...)
	if err != nil && raw == "" {
		return out
	}
	for _, l := range lines(raw) {
		parts := strings.Split(l, "\t")
		if len(parts) != 2 {
			continue
		}
		if i := strings.Index(parts[1], "@"); i > 0 {
			out[parts[0]] = parts[1][i+1:]
		}
	}
	return out
}

// Projects groups containers by compose project.
func Projects(cs []model.Container) map[string][]model.Container {
	out := map[string][]model.Container{}
	for _, c := range cs {
		out[c.Project] = append(out[c.Project], c)
	}
	return out
}
