//! This module defines the configuration file.

use std::{collections::BTreeMap, fs, path::Path};

use json_patch::PatchOperation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
/// The LabelSelector struct is used to match labels in the ConfigMap.
/// It is a reduced version of the Kubernetes LabelSelector, as we only support matching labels. Expressions are not supported.
pub struct LabelSelector {
    #[serde(rename = "matchLabels")]
    pub match_labels: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Selectors {
    pub include: Option<LabelSelector>,
    pub exclude: Option<LabelSelector>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PatchRule {
    pub selectors: Option<Selectors>,
    pub patches: Vec<PatchOperation>,
}

/// Perform the label selector logic to determine if the pod should be selected.
/// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
pub(self) fn run_match_labels(
    labels: &BTreeMap<String, String>,
    match_labels: &BTreeMap<String, String>,
) -> bool {
    match_labels
        .iter()
        .all(|(key, value)| labels.get(key).map_or(false, |v| v == value))
}

impl PatchRule {
    pub fn new(selectors: Option<Selectors>, patches: Vec<PatchOperation>) -> Self {
        Self { selectors, patches }
    }

    pub fn is_matching(&self, labels: &BTreeMap<String, String>) -> bool {
        if let Some(selectors) = &self.selectors {
            // If include is set, we only apply patches to pods that match the labels.
            if let Some(include) = &selectors.include {
                if !run_match_labels(labels, &include.match_labels) {
                    return false;
                }
            }

            // If exclude is set, we skip patches for pods that match the labels. Exclude takes precedence over include.
            if let Some(exclude) = &selectors.exclude {
                if run_match_labels(labels, &exclude.match_labels) {
                    return false;
                }
            }

            return true;
        }
        // If no selectors are set, we apply patches to all pods.
        true
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub rules: Vec<PatchRule>,
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
    use k8s_openapi::api::core::v1::Pod;
    use kube::ResourceExt;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_config_load() {
        let config = Config::from_str(
            r#"
            rules:
            - selectors:
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

        assert_eq!(config.rules.len(), 1);
        let (selectors, patches) = (
            config.rules[0].clone().selectors.unwrap(),
            config.rules[0].clone().patches,
        );

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

    #[test]
    fn test_match_labels() {
        let mut labels = vec![("app".to_string(), "nginx".to_string())]
            .into_iter()
            .collect();
        let match_labels = vec![("app".to_string(), "nginx".to_string())]
            .into_iter()
            .collect();

        assert_eq!(run_match_labels(&labels, &match_labels), true);

        labels.remove("app");

        assert_eq!(run_match_labels(&labels, &match_labels), false);
    }

    #[test]
    fn test_rule_is_matching_no_selectors() {
        let rule: PatchRule = Default::default();
        let pod = Pod::default();

        assert_eq!(rule.is_matching(&pod.labels()), true);
    }

    #[test]
    fn test_rule_is_matching_include() {
        let rule = PatchRule {
            selectors: Some(Selectors {
                include: Some(LabelSelector {
                    match_labels: vec![("app".to_string(), "nginx".to_string())]
                        .into_iter()
                        .collect(),
                }),
                exclude: None,
            }),
            patches: vec![],
        };

        let mut pod = Pod::default();

        assert_eq!(rule.is_matching(&pod.labels()), false);

        pod.metadata.labels = Some(
            vec![("app".to_string(), "nginx".to_string())]
                .into_iter()
                .collect(),
        );

        assert_eq!(rule.is_matching(&pod.labels()), true);
    }

    #[test]
    fn test_rule_is_matching_exclude() {
        let rule = PatchRule {
            selectors: Some(Selectors {
                include: None,
                exclude: Some(LabelSelector {
                    match_labels: vec![("app".to_string(), "nginx".to_string())]
                        .into_iter()
                        .collect(),
                }),
            }),
            patches: vec![],
        };

        let mut pod = Pod::default();

        assert_eq!(rule.is_matching(&pod.labels()), true);

        pod.metadata.labels = Some(
            vec![("app".to_string(), "nginx".to_string())]
                .into_iter()
                .collect(),
        );

        assert_eq!(rule.is_matching(&pod.labels()), false);
    }
}
