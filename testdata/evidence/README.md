# Evidence fixtures

No host capture is committed here. Unit tests build synthetic `.openness` documents in `internal/testfixtures`.

`synthetic/` holds hand-made `.openness` documents (Ubuntu 22.04 with one PyPI package, Ubuntu 24.04, Amazon Linux 2023, Debian 11/12/13, Rocky 9, AlmaLinux 8, RHEL 9, openSUSE Leap 15.6, Alpine 3.20, Windows Server 2022) in the collector schema. They are mock data, not captures. The resolver end-to-end tests (`internal/resolver/distro_e2e_test.go`) and the CLI golden tests (`cmd/openness-resolver/e2e_test.go`, goldens in `cmd/openness-resolver/testdata/golden/`) resolve them against the trimmed feed fixtures in `testdata/feeds/` and `internal/resolver/testdata/msrc/`; the nightly tests (`TestNightlySync`, `.github/workflows/nightly.yml`) sync their real sources from the publishers. Their package versions are deliberately old so the real feeds always report findings. Platforms covered only this way report `platform_tested: false`.

Generated resolver output belongs under `build/` (gitignored).
