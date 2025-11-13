pub mod endpoints;
pub mod error;
pub mod json;

use crate::ContractState;
use error::ServerError;
use matchit::{Params, Router};
use pbc_contract_codegen::off_chain_on_http_request;
use pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData, OffChainContext};
use std::collections::BTreeMap;

/// Helper function to deserialize request body from JSON data
pub fn deserialize_request_body<T>(request: &HttpRequestData) -> Result<T, ServerError>
where
    T: serde::de::DeserializeOwned,
{
    // Parse request body as UTF-8
    let body_str =
        std::str::from_utf8(&request.body).map_err(|_| ServerError::InvalidRequestBody)?;

    // Deserialize JSON
    json::from_str(body_str)
}

/// Helper function to create JSON response
pub fn create_json_response<T>(status_code: u32, data: &T) -> Result<HttpResponseData, ServerError>
where
    T: serde::Serialize,
{
    let json_str = json::to_string(data)?;
    Ok(HttpResponseData::new_with_str(status_code, &json_str))
}

/// Type of functions that can be dispatched to.
///
/// Matches the type of the `off_chain_on_http_request` with HTTP [`Params`].
type DispatchFunction = fn(
    OffChainContext,
    ContractState,
    HttpRequestData,
    Params,
) -> Result<HttpResponseData, HttpResponseData>;

/// Http router to route incoming http requests to its corresponding function
pub struct HttpRouter {
    /// Matchable routes. The key is the HTTP path, and the value is the list of
    /// HTTP methods to be found at that path.
    routes: BTreeMap<String, Vec<HttpMethod>>,
}

impl HttpRouter {
    /// Create a new router
    pub fn new() -> HttpRouter {
        HttpRouter {
            routes: BTreeMap::new(),
        }
    }

    /// Insert a new route to a function
    ///
    /// # Arguments
    ///
    /// * `route` - The route where the method is called
    /// * `method` - The http method and function to call
    pub fn insert(&mut self, route: &str, method: HttpMethod) {
        let vec = self.routes.entry(route.into()).or_default();
        vec.push(method);
    }

    /// Dispatch the http request through the router
    ///
    /// # Arguments
    ///
    /// * `ctx` - the off chain context for accessing external systems
    /// * `state` - the contract state
    /// * `request` - the received http request
    pub fn dispatch(
        self,
        ctx: OffChainContext,
        state: ContractState,
        request: HttpRequestData,
    ) -> Result<HttpResponseData, HttpResponseData> {
        let mut router: Router<Vec<HttpMethod>> = Router::new();
        for (route, methods) in self.routes {
            router.insert(&route, methods).unwrap();
        }

        let uri = request.uri.clone();
        let routed = router
            .at(&uri)
            .map_err(|_| HttpResponseData::new_with_str(404, &json::json_error("Invalid URL")))?;

        let methods = routed.value;

        let dispatch = methods
            .iter()
            .find(|method| method.method_type() == request.method.as_str().to_lowercase())
            .ok_or_else(|| {
                HttpResponseData::new_with_str(405, &json::json_error("Invalid method"))
            })?
            .get_function();

        dispatch(ctx, state, request, routed.params)
    }
}

/// Http method that can be called by the router
pub enum HttpMethod {
    /// Get method
    #[allow(dead_code)]
    Get(DispatchFunction),
    /// Put method
    #[allow(dead_code)]
    Put(DispatchFunction),
    /// Post method
    Post(DispatchFunction),
}

impl HttpMethod {
    /// Get the method type as a string
    pub fn method_type(&self) -> &str {
        match self {
            HttpMethod::Get(_) => "get",
            HttpMethod::Put(_) => "put",
            HttpMethod::Post(_) => "post",
        }
    }

    /// Get the rust function of this http method
    pub fn get_function(&self) -> &DispatchFunction {
        match self {
            HttpMethod::Get(function) => function,
            HttpMethod::Put(function) => function,
            HttpMethod::Post(function) => function,
        }
    }
}

/// Register all routes with the router
fn register_routes(router: &mut HttpRouter) {
    use endpoints::{account, association, init, reconstruction};

    // Register routes for each module
    association::register_routes(router);
    account::register_routes(router);
    reconstruction::register_routes(router);

    // Register init endpoint
    router.insert(
        init::PATH,
        HttpMethod::Post(|ctx, state, request, params| {
            init::handler(ctx, state, request, params)
                .map_err(error::contract_error_to_http_response)
        }),
    );
}

/// Main HTTP dispatch function for the contract
#[off_chain_on_http_request]
pub fn http_dispatch(
    ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
) -> HttpResponseData {
    let mut router: HttpRouter = HttpRouter::new();

    // Register all routes
    register_routes(&mut router);

    let result = router.dispatch(ctx, state, request);
    result.unwrap_or_else(|err| err)
}
