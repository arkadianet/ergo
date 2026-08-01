use std::collections::BTreeSet;

use axum::routing::MethodRouter;
use axum::Router;

use crate::api_family::ApiFamily;

use super::RouteOperation;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiRouteInventory {
    pub scala: BTreeSet<RouteOperation>,
    pub rust: BTreeSet<RouteOperation>,
}

impl ApiRouteInventory {
    fn extend(&mut self, family: ApiFamily, operations: BTreeSet<RouteOperation>) {
        match family {
            ApiFamily::Scala => self.scala.extend(operations),
            ApiFamily::Rust => self.rust.extend(operations),
        }
    }
}

pub(super) struct FamilyRouter<S = ()> {
    family: ApiFamily,
    router: Router<S>,
    operations: BTreeSet<RouteOperation>,
}

impl<S> FamilyRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    pub(super) fn new(family: ApiFamily) -> Self {
        Self {
            family,
            router: Router::new(),
            operations: BTreeSet::new(),
        }
    }

    pub(super) fn route(
        mut self,
        axum_path: &'static str,
        openapi_path: &'static str,
        methods: &'static [&'static str],
        method_router: MethodRouter<S>,
    ) -> Self {
        self.router = self.router.route(axum_path, method_router);
        self.operations.extend(
            methods
                .iter()
                .map(|method| RouteOperation::new(openapi_path, method)),
        );
        self
    }

    pub(super) fn merge(mut self, other: Self) -> Self {
        assert_eq!(self.family, other.family);
        self.router = self.router.merge(other.router);
        self.operations.extend(other.operations);
        self
    }

    pub(super) fn merge_documented(
        mut self,
        router: Router<S>,
        operations: impl IntoIterator<Item = RouteOperation>,
    ) -> Self {
        self.router = self.router.merge(router);
        self.operations.extend(operations);
        self
    }

    pub(super) fn route_layer<L>(mut self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::extract::Request> + Clone + Send + Sync + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Response:
            axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Error:
            Into<std::convert::Infallible> + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Future: Send + 'static,
    {
        self.router = self.router.route_layer(layer);
        self
    }

    pub(super) fn with_state<S2>(self, state: S) -> FamilyRouter<S2>
    where
        S2: Clone + Send + Sync + 'static,
    {
        FamilyRouter {
            family: self.family,
            router: self.router.with_state(state),
            operations: self.operations,
        }
    }

    pub(super) fn into_parts(self) -> (ApiFamily, Router<S>, BTreeSet<RouteOperation>) {
        (self.family, self.router, self.operations)
    }
}

pub(super) fn merge_family_router(
    router: Router,
    inventory: &mut ApiRouteInventory,
    family_router: FamilyRouter,
) -> Router {
    let (family, family_router, operations) = family_router.into_parts();
    inventory.extend(family, operations);
    router.merge(family_router)
}
