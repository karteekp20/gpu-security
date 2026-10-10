Triton requires `--model-repository` to point at a directory that exists. It
does not need a model in it: with `--model-control-mode=explicit` and
`--strict-readiness=false`, the server starts, `/v2/health/ready` returns 200,
and `/metrics` serves on 8002 — which is all `RG-TRITON-001/-002/-003` need.

This directory is deliberately empty. Loading a real model would need a GPU
for most backends and would prove nothing extra about exposure.
