# Security

## Model bundles are pickles

`gaphunter export-model` writes a joblib (pickle) file. Loading a pickle runs code from
that file, so `gaphunter detect -m` and `gaphunter explain -m` must only be given bundles
that you or someone you trust created. Treat bundles like executables: do not download
them from untrusted sources, and store them where only trusted users can write.

## Scope

GapHunter is a defensive measurement and detection tool. It contains no exploits,
payloads or evasion techniques and does not execute adversary emulation.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository
(Security > Advisories > Report a vulnerability) rather than a public issue.
