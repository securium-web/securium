# Downstream-Owned Source

Substantial Chromium Secure-owned implementations belong here rather than in
large patches to Chromium-owned files. Future deterministic integration tooling
will copy or inject these files into an exact Chromium checkout before patch and
build qualification.

This directory currently contains documentation only. It does not implement
secure profiles, a key provider, secret migration, or cryptography.
