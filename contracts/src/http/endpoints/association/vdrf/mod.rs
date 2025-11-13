pub mod eval;

use crate::http::{error::contract_error_to_http_response, HttpMethod, HttpRouter};

pub fn register_routes(router: &mut HttpRouter) {
    router.insert(
        eval::PATH,
        HttpMethod::Post(|ctx, state, request, params| {
            eval::handler(ctx, state, request, params).map_err(contract_error_to_http_response)
        }),
    );
}
