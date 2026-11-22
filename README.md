# bkprobe

WAR-01 measurement probe for the target's BuildKit build pipeline (`moby/buildkit` v0.17.3,
rootless image, `--oci-worker-no-process-sandbox`).

`Dockerfile` runs `probe.js` inside a `RUN` step, so every value in the report is measured from the
build sandbox, not from the runtime container. The report is written to `/app/probe-report.json`
during the build and served by `server.js` on port 8080 at deploy time.

## What it measures

| Field | Question it answers |
|---|---|
| `self-status` | uid/gid, `CapEff`, `NoNewPrivs`, `Seccomp*` of the build step |
| `pid-enumeration`, `proc1-cmdline` | does the build share a PID namespace with `buildkitd`, and is `--oci-worker-no-process-sandbox` in the daemon argv |
| `daemon-root-visibility`, `version-from-daemon-binary` | whether `/proc/<pid>/root` of the daemon is traversable (errno) |
| `path-candidates`, `bounded-filesystem-scan` | `/.buildkit`, `/run/buildkit`, socket paths visible in the sandbox |
| `mountinfo` | how the daemon state dir (`/home/user/.local/share/buildkit/...`) leaks into the sandbox mount table |
| `host-path-write-test` | errno for write permission on daemon-side paths, using `access(W_OK)` and `open(...,'r')` only, never creating a file |
| `signal-reachability` | `kill(pid,0)` acceptance for `buildkitd` (permission test, no kill sent) |
| `yama-and-kernel-limits` | `ptrace_scope`, userns limits |
| `version-token-scan` | version/state-path tokens in any readable `/proc/<pid>/cmdline` or `environ` |
| `daemon-mountinfo-and-cgroup` | whether `/proc/<pid>/mountinfo` of the daemon is readable (this is what would prove a host bind mount) |
| `sandbox-egress` | TCP reachability from the build step |

## Deploy contract

Anonymous try path: `POST /v1/try` with `{"repo":"https://github.com/xophydra/bkprobe"}`.
`EXPOSE 8080` is present; `GET /healthz` answers for the health check; `GET /` returns the JSON report.

## Locally reproduced facts

Against a local `moby/buildkit:v0.17.3` daemon (rootless image, `--oci-worker-no-process-sandbox`),
driven with the image's own `buildctl`: the sandbox's own `/` overlay has
`lowerdir=`/`upperdir=` inside `/home/user/.local/share/buildkit/runc-overlayfs/snapshots/...`,
`/proc/1/cmdline` contains the flag, `/proc/<pid>/root` returns `EACCES`, and `kill(pid,0)` on
`buildkitd` is accepted.
