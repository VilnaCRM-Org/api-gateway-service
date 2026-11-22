use rstest::rstest;
use serde_json::{Value, json};

use super::*;

fn json_document() -> Value {
    serde_json::to_value(document()).unwrap()
}

#[rstest]
#[case(
    "/api/health",
    "get",
    "api_health_get",
    "HealthCheck",
    ("Checks the health of the service.", "Returns 204 when the database, the cache and the message broker respond. Returns a 500 problem document that lists every failing dependency otherwise.", "204 500 default")
)]
#[case(
    "/api/example_api_resources",
    "get",
    "api_example_api_resources_get",
    "ExampleApiResource",
    ("Retrieves the collection of ExampleApiResource resources.", "Returns one page of resources, newest first.", "200 400 422 default")
)]
#[case(
    "/api/example_api_resources",
    "post",
    "api_example_api_resources_post",
    "ExampleApiResource",
    ("Creates an ExampleApiResource resource.", "Validates the input, stores the resource and returns it.", "201 400 413 415 422 default")
)]
#[case(
    "/api/example_api_resources/{id}",
    "get",
    "api_example_api_resources_id_get",
    "ExampleApiResource",
    ("Retrieves an ExampleApiResource resource.", "Returns the resource identified by id.", "200 400 404 default")
)]
fn documents_every_operation(
    #[case] path: &str,
    #[case] method: &str,
    #[case] operation_id: &str,
    #[case] tag: &str,
    #[case] texts: (&str, &str, &str),
) {
    let (summary, description, statuses) = texts;
    let json = json_document();
    let operation = &json["paths"][path][method];

    assert_eq!(operation["operationId"], operation_id);
    assert_eq!(operation["tags"], json!([tag]));
    assert_eq!(operation["summary"], summary);
    assert_eq!(operation["description"], description);
    let mut documented: Vec<&str> = operation["responses"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    documented.sort_unstable();
    assert_eq!(documented, statuses.split(' ').collect::<Vec<_>>());
    assert_eq!(
        operation["responses"]["default"]["description"],
        "Problem response."
    );
    assert_eq!(
        operation["responses"]["default"]["content"]["application/problem+json"]["schema"]["$ref"],
        "#/components/schemas/Problem"
    );
}

#[test]
fn documents_exactly_the_eight_operations() {
    let json = json_document();
    let mut operations = Vec::new();
    for (path, item) in json["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            operations.push(format!("{method} {path}"));
        }
    }

    assert_eq!(
        operations,
        [
            "get /api/example_api_resources",
            "post /api/example_api_resources",
            "get /api/example_api_resources/{id}",
            "get /api/health",
            "get /api/roles",
            "post /api/roles",
            "get /api/roles/{id}",
            "post /api/token-resolutions",
        ]
    );
}

#[test]
fn leaves_the_liveness_route_and_the_docs_routes_out() {
    let json = json_document();
    let paths = json["paths"].as_object().unwrap();

    assert!(!paths.contains_key("/ping"));
    assert!(paths.keys().all(|path| !path.starts_with("/api/docs")));
    assert!(!paths.keys().any(|path| path.contains("graphql")));
}

#[test]
fn carries_the_service_identity_and_the_contract_version() {
    let info = &json_document()["info"];

    assert_eq!(json_document()["openapi"], "3.1.0");
    assert_eq!(
        info["title"],
        concat!(env!("CARGO_PKG_DESCRIPTION"), " API")
    );
    assert_eq!(
        info["description"],
        format!(
            "This API provides endpoints to manage {} data within VilnaCRM.",
            env!("CARGO_PKG_DESCRIPTION")
        )
    );
    assert_eq!(info["version"], "1.0.0");
    assert_eq!(info["version"], API_VERSION);
    assert_eq!(
        info["contact"],
        json!({
            "name": "VilnaCRM Support",
            "url": env!("CARGO_PKG_REPOSITORY"),
            "email": "support@vilnacrm.com",
        })
    );
    assert_eq!(
        info["license"],
        json!({
            "name": "CC0-1.0",
            "url": "https://creativecommons.org/publicdomain/zero/1.0/",
        })
    );
}

#[test]
fn the_identity_comes_from_the_package_manifest_and_is_never_empty() {
    assert_ne!(env!("CARGO_PKG_DESCRIPTION"), "");
    assert!(env!("CARGO_PKG_REPOSITORY").starts_with("https://"));
}

#[test]
fn documents_the_token_resolution_with_the_bearer_requirement_and_the_iam_tag() {
    let json = json_document();
    let operation = &json["paths"]["/api/token-resolutions"]["post"];

    assert_eq!(operation["operationId"], "api_token_resolutions_post");
    assert_eq!(operation["tags"], json!(["iam"]));
    assert_eq!(operation["security"], json!([{ "bearerAuth": [] }]));
    let mut documented: Vec<&str> = operation["responses"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    documented.sort_unstable();
    assert_eq!(
        documented,
        ["200", "400", "401", "403", "413", "415", "422", "default"]
    );
    for status in ["400", "401", "403", "413", "415", "422", "default"] {
        assert_eq!(
            operation["responses"][status]["content"]["application/problem+json"]["schema"]["$ref"],
            "#/components/schemas/Problem",
            "{status}"
        );
    }
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/TokenResolution"
    );
    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/TokenResolutionRequest"
    );
}

#[test]
fn documents_the_role_operations_with_the_bearer_requirement_and_the_iam_tag() {
    let json = json_document();
    let cases = [
        (
            "/api/roles",
            "post",
            "api_roles_post",
            ["201", "400", "401", "409", "413", "415", "422", "default"].as_slice(),
        ),
        (
            "/api/roles",
            "get",
            "api_roles_get",
            ["200", "400", "401", "422", "default"].as_slice(),
        ),
        (
            "/api/roles/{id}",
            "get",
            "api_roles_id_get",
            ["200", "400", "401", "404", "422", "default"].as_slice(),
        ),
    ];

    for (path, method, operation_id, statuses) in cases {
        let operation = &json["paths"][path][method];
        assert_eq!(operation["operationId"], operation_id);
        assert_eq!(operation["tags"], json!(["iam"]), "{operation_id}");
        assert_eq!(
            operation["security"],
            json!([{ "bearerAuth": [] }]),
            "{operation_id}"
        );
        let mut documented: Vec<&str> = operation["responses"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        documented.sort_unstable();
        assert_eq!(documented, statuses, "{operation_id}");
        for status in statuses
            .iter()
            .filter(|status| **status != "200" && **status != "201")
        {
            assert_eq!(
                operation["responses"][status]["content"]["application/problem+json"]["schema"]["$ref"],
                "#/components/schemas/Problem",
                "{operation_id} {status}"
            );
        }
    }
}

#[test]
fn the_role_creation_documents_its_request_headers_and_schemas() {
    let json = json_document();
    let operation = &json["paths"]["/api/roles"]["post"];

    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/CreateRoleRequest"
    );
    assert_eq!(
        operation["responses"]["201"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/Role"
    );
    let headers: Vec<&str> = operation["responses"]["201"]["headers"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(headers, ["etag", "location"]);
    let parameters = operation["parameters"].as_array().unwrap();
    assert_eq!(parameters.len(), 1);
    assert_eq!(parameters[0]["name"], "Idempotency-Key");
    assert_eq!(parameters[0]["in"], "header");
    let schemas = &json["components"]["schemas"];
    assert_eq!(schemas["CreateRoleRequest"]["additionalProperties"], false);
    assert_eq!(schemas["CreateRoleRequest"]["required"], json!(["name"]));
    assert_eq!(
        schemas["CreateRoleRequest"]["properties"]["name"]["maxLength"],
        100
    );
    assert_eq!(
        schemas["CreateRoleRequest"]["properties"]["description"]["maxLength"],
        1000
    );
    assert!(
        schemas["RolePage"]["properties"]
            .get("nextCursor")
            .is_some()
    );
}

#[test]
fn the_role_list_documents_its_query_parameters() {
    let json = json_document();
    let operation = &json["paths"]["/api/roles"]["get"];

    let mut names: Vec<&str> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|parameter| parameter["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["after", "kind", "limit", "namePrefix"]);
    assert_eq!(
        json["paths"]["/api/roles/{id}"]["get"]["parameters"][0]["in"],
        "path"
    );
}

#[test]
fn the_bearer_scheme_is_an_http_bearer_jwt_scheme() {
    let json = json_document();

    assert_eq!(BEARER_AUTH, "bearerAuth");
    let scheme = &json["components"]["securitySchemes"]["bearerAuth"];
    assert_eq!(scheme["type"], "http");
    assert_eq!(scheme["scheme"], "bearer");
    assert_eq!(scheme["bearerFormat"], "JWT");
}

#[test]
fn the_token_resolution_schemas_never_echo_the_credential() {
    let json = json_document();
    let schemas = &json["components"]["schemas"];

    assert_eq!(
        schemas["TokenResolutionRequest"]["properties"]["credential"]["maxLength"],
        8192
    );
    assert_eq!(
        schemas["TokenResolutionRequest"]["additionalProperties"],
        false
    );
    assert!(
        schemas["TokenResolution"]["properties"]
            .get("credential")
            .is_none()
    );
    assert_eq!(schemas["TokenResolution"]["required"], json!(["resolved"]));
}

#[test]
fn carries_the_server_the_tags_and_only_the_bearer_scheme() {
    let json = json_document();

    assert_eq!(
        json["servers"],
        json!([{ "url": "/", "description": "Current host" }])
    );
    let mut tags = json["tags"].as_array().unwrap().clone();
    tags.sort_by_key(|tag| tag["name"].as_str().map(str::to_owned));
    assert_eq!(
        tags,
        [
            json!({ "name": "ExampleApiResource", "description": "Template example resource endpoints." }),
            json!({ "name": "HealthCheck", "description": "Runtime health-check endpoints." }),
            json!({ "name": "iam", "description": "IAM endpoints: authentication and authorization of API callers." }),
        ]
    );
    let schemes: Vec<&str> = json["components"]["securitySchemes"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(schemes, ["bearerAuth"]);
    assert!(json.get("security").is_none());
}

#[test]
fn defines_exactly_the_ten_schemas() {
    let json = json_document();
    let schemas = json["components"]["schemas"].as_object().unwrap();

    let names: Vec<&str> = schemas.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "CreateExampleApiResourceRequest",
            "CreateRoleRequest",
            "DependencyFailure",
            "ExampleApiResource",
            "Problem",
            "Role",
            "RolePage",
            "TokenResolution",
            "TokenResolutionRequest",
            "Violation"
        ]
    );
    assert_eq!(
        schemas["CreateExampleApiResourceRequest"]["additionalProperties"],
        false
    );
    assert_eq!(
        schemas["ExampleApiResource"]["properties"]["id"]["format"],
        "uuid"
    );
}

#[test]
fn the_create_response_documents_the_location_header() {
    let json = json_document();

    let created = &json["paths"]["/api/example_api_resources"]["post"]["responses"]["201"];
    assert!(created["headers"]["location"].is_object());
}

#[test]
fn the_yaml_is_the_document_in_yaml() {
    let text = yaml().unwrap();

    assert!(text.starts_with("openapi: 3.1.0\n"));
    assert!(text.contains("operationId: api_health_get\n"));
    assert!(text.ends_with('\n'));
}

#[test]
fn twenty_generations_are_byte_identical() {
    let first = yaml().unwrap();

    for _ in 0..20 {
        assert_eq!(yaml().unwrap(), first);
    }
}

#[test]
fn an_export_error_names_the_document_and_keeps_its_cause() {
    let cause = std::io::Error::other("disk on fire");

    let error = ExportError::new(cause);

    assert_eq!(
        error.to_string(),
        "the OpenAPI document could not be serialised"
    );
    let source = std::error::Error::source(&error).unwrap();
    assert_eq!(source.to_string(), "disk on fire");
}
