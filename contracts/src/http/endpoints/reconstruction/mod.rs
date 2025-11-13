pub mod get_shares;
pub mod upload_share;

use crate::http::{error::contract_error_to_http_response, HttpMethod, HttpRouter};

pub fn register_routes(router: &mut HttpRouter) {
    router.insert(
        upload_share::PATH,
        HttpMethod::Post(|ctx, state, request, params| {
            upload_share::handler(ctx, state, request, params)
                .map_err(contract_error_to_http_response)
        }),
    );
    router.insert(
        get_shares::PATH,
        HttpMethod::Post(|ctx, state, request, params| {
            get_shares::handler(ctx, state, request, params)
                .map_err(contract_error_to_http_response)
        }),
    );
}
