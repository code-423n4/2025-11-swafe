pub mod get_secret_share;
pub mod upload_msk;
pub mod vdrf;

use crate::http::{error::contract_error_to_http_response, HttpMethod, HttpRouter};

pub fn register_routes(router: &mut HttpRouter) {
    // Register VDRF routes
    vdrf::register_routes(router);

    // Register other association routes
    router.insert(
        upload_msk::PATH,
        HttpMethod::Post(|ctx, state, request, params| {
            upload_msk::handler(ctx, state, request, params)
                .map_err(contract_error_to_http_response)
        }),
    );
    router.insert(
        get_secret_share::PATH,
        HttpMethod::Post(|ctx, state, request, params| {
            get_secret_share::handler(ctx, state, request, params)
                .map_err(contract_error_to_http_response)
        }),
    );
}
