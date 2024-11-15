//! This module defines the configuration file.

use std::{fs, path::Path};

use json_patch::PatchOperation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub selectors: Option<Selectors>,
    pub patches: Vec<PatchOperation>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
/// The LabelSelector struct is used to match labels in the ConfigMap.
/// It is a reduced version of the Kubernetes LabelSelector, as we only support matching labels. Expressions are not supported.
pub struct LabelSelector {
    #[serde(rename = "matchLabels")]
    pub match_labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Selectors {
    pub include: Option<LabelSelector>,
    pub exclude: Option<LabelSelector>,
}

impl Config {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(serde_yaml::from_str(s)?)
    }

    pub fn from_file(file_path: &Path) -> anyhow::Result<Self> {
        let config_content = fs::read_to_string(file_path)?;
        Self::from_str(&config_content)
    }
}

#[cfg(test)]
mod tests {
    use json_patch::AddOperation;
    use jsonptr::Pointer;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_config_load() {
        let config = Config::from_str(
            r#"
            selectors:
              exclude:
                matchLabels:
                  kite.io/no-patch: "true"
            patches:
              - op: add
                path: /metadata/labels
                value: {}
              - op: add
                path: /metadata/labels/kite.io~1patched
                value: "true"
              - op: add
                path: /metadata/annotations
                value: {}
              - op: add
                path: /metadata/annotations/kite.io~1monitored
                value: "true"
              - op: add
                path: /spec/volumes
                value: []
              - op: add
                path: /spec/volumes/-
                value:
                  name: kite-socket
                  hostPath:
                    type: Socket
                    path: /var/run/kite/kite.sock
              - op: add
                path: /spec/initContainers
                value: []
              - op: add
                path: /spec/initContainers/-
                value:
                  name: kite
                  image: kite:dev
                  command: ["kite-init-container"]
                  volumeMounts:
                    - name: kite-socket
                      mountPath: /var/run/kite/kite.sock
                  env:
                    - name: KITE_POD_NAME
                      valueFrom:
                        fieldRef:
                          fieldPath: metadata.name
                    - name: KITE_POD_NAMESPACE
                      valueFrom:
                        fieldRef:
                          fieldPath: metadata.namespace
                    - name: KITE_SOCK
                      value: /var/run/kite/kite.sock
    
        "#,
        )
        .unwrap();

        let selectors = config.selectors.unwrap();
        let patches = config.patches;

        assert!(selectors.include.is_none());
        assert_eq!(
            selectors
                .exclude
                .unwrap()
                .match_labels
                .get("kite.io/no-patch")
                .unwrap(),
            "true"
        );
        assert_eq!(
            patches[0],
            PatchOperation::Add(json_patch::AddOperation {
                path: Pointer::new(["metadata", "labels"]),
                value: json!({}),
            })
        );
        let init_container = json!({
            "name": "kite",
            "image": "kite:dev",
            "command": ["kite-init-container"],
            "volumeMounts": [
                {
                    "name": "kite-socket",
                    "mountPath": "/var/run/kite/kite.sock",
                }
            ],
            "env": [
                {
                    "name": "KITE_POD_NAME",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.name"
                        }
                    }
                },
                {
                    "name": "KITE_POD_NAMESPACE",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.namespace"
                        }
                    }
                },
                {
                    "name": "KITE_SOCK",
                    "value": "/var/run/kite/kite.sock"
                }
            ]
        });

        assert_eq!(
            patches.last().unwrap(),
            &PatchOperation::Add(AddOperation {
                path: Pointer::new(["spec", "initContainers", "-"]),
                value: init_container,
            }),
        );
    }
}
