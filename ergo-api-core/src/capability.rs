use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CapabilityId {
    Node,
    Chain,
    Mempool,
    Transactions,
    Indexer,
    Mining,
    Wallet,
    Scripts,
    Realtime,
    Webhooks,
    Administration,
}

impl CapabilityId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Chain => "chain",
            Self::Mempool => "mempool",
            Self::Transactions => "transactions",
            Self::Indexer => "indexer",
            Self::Mining => "mining",
            Self::Wallet => "wallet",
            Self::Scripts => "scripts",
            Self::Realtime => "realtime",
            Self::Webhooks => "webhooks",
            Self::Administration => "administration",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityState {
    Available,
    Disabled,
    Unavailable,
}

impl CapabilityState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Disabled => "disabled",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityReason {
    DisabledByConfig,
    UnsupportedState(&'static str),
    StartupFailed(String),
    TemporarilyUnavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDescriptor {
    pub id: CapabilityId,
    pub state: CapabilityState,
    pub reason: Option<CapabilityReason>,
}

impl CapabilityDescriptor {
    pub fn available(id: CapabilityId) -> Self {
        Self {
            id,
            state: CapabilityState::Available,
            reason: None,
        }
    }

    pub fn disabled(id: CapabilityId) -> Self {
        Self {
            id,
            state: CapabilityState::Disabled,
            reason: Some(CapabilityReason::DisabledByConfig),
        }
    }

    pub fn unavailable(id: CapabilityId, reason: CapabilityReason) -> Self {
        Self {
            id,
            state: CapabilityState::Unavailable,
            reason: Some(reason),
        }
    }
}

pub enum Capability<T> {
    Available(Arc<T>),
    Unavailable(CapabilityReason),
}

impl<T> Capability<T> {
    pub fn available(value: Arc<T>) -> Self {
        Self::Available(value)
    }

    pub fn unavailable(reason: CapabilityReason) -> Self {
        Self::Unavailable(reason)
    }

    pub fn get(&self) -> Option<&Arc<T>> {
        match self {
            Self::Available(value) => Some(value),
            Self::Unavailable(_) => None,
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    pub fn descriptor(&self, id: CapabilityId) -> CapabilityDescriptor {
        match self {
            Self::Available(_) => CapabilityDescriptor::available(id),
            Self::Unavailable(CapabilityReason::DisabledByConfig) => {
                CapabilityDescriptor::disabled(id)
            }
            Self::Unavailable(reason) => CapabilityDescriptor::unavailable(id, reason.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_capability_has_no_value() {
        let capability: Capability<()> =
            Capability::unavailable(CapabilityReason::DisabledByConfig);
        assert!(!capability.is_available());
        assert_eq!(
            capability.descriptor(CapabilityId::Wallet).state,
            CapabilityState::Disabled
        );
    }
}
