pub mod get;

use crate::http::{error::contract_error_to_http_response, HttpMethod, HttpRouter};

pub fn register_routes(router: &mut HttpRouter) {
    router.insert(
        get::PATH,
        HttpMethod::Post(|ctx, state, request, params| {
            get::handler(ctx, state, request, params).map_err(contract_error_to_http_response)
        }),
    );
}
