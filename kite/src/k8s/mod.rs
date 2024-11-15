/// This module is responsible for interfacing with Kubernetes.
pub mod pods;

pub mod consts {
    pub const ENV_KITE_POD_NAME: &str = "KITE_POD_NAME";
    pub const ENV_KITE_POD_NAMESPACE: &str = "KITE_POD_NAMESPACE";
    pub const LABEL_NO_PATCH: &str = "kite.io/no-patch";
    pub const ANNOTATION_MONITORED: &str = "kite.io/monitored";
}
