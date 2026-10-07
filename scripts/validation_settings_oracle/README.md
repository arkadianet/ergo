With Java 21, Scala CLI and locally published ergo-core 6.0.7:

```bash
export COURSIER_REPOSITORIES='ivy2Local|https://repo.maven.apache.org/maven2'
scala-cli run scripts/validation_settings_oracle/ValidationSettingsOracle.scala \
  --server=false --jvm system -- \
  test-vectors/reference-6.0.7/validation-settings/settings.json
```

The oracle obtains extension chunks from `ErgoValidationSettings.toExtensionCandidate`,
and separately tests update deserialization and complete settings deserialization.
It records the node's initial Sigma map and the disableable node rules.
