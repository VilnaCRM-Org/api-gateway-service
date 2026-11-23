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
fn documents_exactly_the_twenty_four_operations() {
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
            "get /api/graphql-specs",
            "post /api/graphql-specs",
            "get /api/graphql-specs/{id}",
            "get /api/graphql-specs/{id}/diff",
            "post /api/graphql-specs/{id}/permissions",
            "get /api/health",
            "get /api/openapi-specs",
            "post /api/openapi-specs",
            "get /api/openapi-specs/{id}",
            "get /api/openapi-specs/{id}/diff",
            "get /api/roles",
            "post /api/roles",
            "get /api/roles/{id}",
            "delete /api/roles/{id}",
            "patch /api/roles/{id}",
            "post /api/token-resolutions",
            "get /api/user-roles",
            "post /api/user-roles",
            "get /api/user-roles/{id}",
            "delete /api/user-roles/{id}",
            "patch /api/user-roles/{id}",
        ]
    );
}

#[test]
fn leaves_the_liveness_route_and_the_docs_routes_out() {
    let json = json_document();
    let paths = json["paths"].as_object().unwrap();

    assert!(!paths.contains_key("/ping"));
    assert!(paths.keys().all(|path| !path.starts_with("/api/docs")));
    assert!(!paths.contains_key("/api/graphql"));
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
        (
            "/api/roles/{id}",
            "patch",
            "api_roles_id_patch",
            [
                "200", "400", "401", "403", "404", "409", "412", "413", "415", "422", "428",
                "default",
            ]
            .as_slice(),
        ),
        (
            "/api/roles/{id}",
            "delete",
            "api_roles_id_delete",
            [
                "200", "400", "401", "403", "404", "409", "412", "422", "428", "default",
            ]
            .as_slice(),
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
fn the_role_deletion_documents_its_headers_and_the_revoked_assignments() {
    let json = json_document();
    let operation = &json["paths"]["/api/roles/{id}"]["delete"];

    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/DeletedRole"
    );
    assert!(operation["responses"]["200"]["headers"]["etag"].is_object());
    assert!(operation["responses"]["200"]["headers"]["iam-policy-version"].is_object());
    let names: Vec<&str> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|parameter| parameter["name"].as_str())
        .collect();
    assert_eq!(names, ["id", "If-Match", "Idempotency-Key"]);
    let schema = &json["components"]["schemas"]["DeletedRole"];
    assert_eq!(schema["required"], json!(["id", "revokedAssignments"]));
    assert_eq!(schema["properties"]["revokedAssignments"]["minimum"], 0);
}

#[test]
fn documents_the_graphql_specification_upload_with_its_statuses_and_schemas() {
    let json = json_document();
    let operation = &json["paths"]["/api/graphql-specs"]["post"];

    assert_eq!(operation["operationId"], "api_graphql_specs_post");
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
        [
            "200", "201", "400", "401", "403", "409", "413", "415", "422", "default"
        ]
    );
    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/LoadGraphQlSpecRequest"
    );
    for status in ["200", "201"] {
        assert_eq!(
            operation["responses"][status]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/GraphQlSpec",
            "{status}"
        );
        assert!(operation["responses"][status]["headers"]["location"].is_object());
    }
}

#[test]
fn documents_the_openapi_specification_upload_with_its_statuses_and_schemas() {
    let json = json_document();
    let operation = &json["paths"]["/api/openapi-specs"]["post"];

    assert_eq!(operation["operationId"], "api_openapi_specs_post");
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
        [
            "200", "201", "400", "401", "403", "409", "413", "415", "422", "default"
        ]
    );
    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/LoadOpenApiSpecRequest"
    );
    for status in ["200", "201"] {
        assert_eq!(
            operation["responses"][status]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/OpenApiSpec",
            "{status}"
        );
        assert!(operation["responses"][status]["headers"]["location"].is_object());
    }
    let request = &json["components"]["schemas"]["LoadOpenApiSpecRequest"];
    assert_eq!(request["additionalProperties"], false);
    assert_eq!(request["required"], json!(["service", "document"]));
}

#[test]
fn documents_the_graphql_specification_reads_with_the_bearer_requirement_and_the_iam_tag() {
    let json = json_document();
    let cases = [
        (
            "/api/graphql-specs",
            "api_graphql_specs_get",
            ["200", "400", "401", "422", "default"].as_slice(),
            "#/components/schemas/GraphQlSpecPage",
        ),
        (
            "/api/graphql-specs/{id}",
            "api_graphql_specs_id_get",
            ["200", "400", "401", "404", "422", "default"].as_slice(),
            "#/components/schemas/GraphQlSpecSummary",
        ),
        (
            "/api/graphql-specs/{id}/diff",
            "api_graphql_specs_id_diff_get",
            ["200", "400", "401", "404", "422", "default"].as_slice(),
            "#/components/schemas/GraphQlSpecDiff",
        ),
    ];

    for (path, operation_id, statuses, schema) in cases {
        let operation = &json["paths"][path]["get"];
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
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"], schema,
            "{operation_id}"
        );
    }
}

#[test]
fn the_graphql_activation_documents_its_responses_headers_and_schemas() {
    let json = json_document();
    let operation = &json["paths"]["/api/graphql-specs/{id}/permissions"]["post"];

    assert_eq!(
        operation["operationId"],
        "api_graphql_specs_id_permissions_post"
    );
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
        [
            "200", "201", "400", "401", "404", "409", "413", "415", "422", "default"
        ]
    );
    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/CreateGraphQlPermissionsRequest"
    );
    for status in ["200", "201"] {
        assert_eq!(
            operation["responses"][status]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/GraphQlPermissionsActivation",
            "{status}"
        );
        assert!(operation["responses"][status]["headers"]["iam-policy-version"].is_object());
    }
    let names: Vec<&str> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|parameter| parameter["name"].as_str())
        .collect();
    assert_eq!(names, ["id", "Idempotency-Key"]);
    let request = &json["components"]["schemas"]["CreateGraphQlPermissionsRequest"];
    assert_eq!(request["additionalProperties"], false);
    assert!(request["properties"]["renames"].is_object());
}

#[test]
fn the_graphql_specification_reads_document_their_query_parameters() {
    let json = json_document();
    let names = |path: &str| -> Vec<String> {
        let mut names: Vec<String> = json["paths"][path]["get"]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|parameter| parameter["name"].as_str().unwrap().to_owned())
            .collect();
        names.sort_unstable();
        names
    };

    assert_eq!(
        names("/api/graphql-specs"),
        ["after", "includeSdl", "limit", "service", "status"]
    );
    assert_eq!(names("/api/graphql-specs/{id}"), ["id", "includeSdl"]);
    assert_eq!(names("/api/graphql-specs/{id}/diff"), ["id"]);
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
fn the_role_update_documents_its_request_headers_and_schemas() {
    let json = json_document();
    let operation = &json["paths"]["/api/roles/{id}"]["patch"];

    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/UpdateRoleRequest"
    );
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/Role"
    );
    let headers: Vec<&str> = operation["responses"]["200"]["headers"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(headers, ["etag"]);
    let parameters: Vec<(&str, &str, bool)> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|parameter| {
            (
                parameter["name"].as_str().unwrap(),
                parameter["in"].as_str().unwrap(),
                parameter["required"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    assert_eq!(
        parameters,
        [
            ("id", "path", true),
            ("If-Match", "header", true),
            ("Idempotency-Key", "header", false)
        ]
    );
    let schema = &json["components"]["schemas"]["UpdateRoleRequest"];
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema.get("required").is_none());
    assert_eq!(schema["properties"]["name"]["maxLength"], 100);
    assert_eq!(schema["properties"]["description"]["maxLength"], 1000);
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
fn documents_the_assignment_operations_with_the_bearer_requirement_and_the_iam_tag() {
    let json = json_document();
    let cases = [
        (
            "/api/user-roles",
            "post",
            "api_user_roles_post",
            ["201", "400", "401", "409", "413", "415", "422", "default"].as_slice(),
        ),
        (
            "/api/user-roles",
            "get",
            "api_user_roles_get",
            ["200", "400", "401", "422", "default"].as_slice(),
        ),
        (
            "/api/user-roles/{id}",
            "get",
            "api_user_roles_id_get",
            ["200", "400", "401", "404", "422", "default"].as_slice(),
        ),
        (
            "/api/user-roles/{id}",
            "patch",
            "api_user_roles_id_patch",
            [
                "200", "400", "401", "404", "412", "413", "415", "422", "428", "default",
            ]
            .as_slice(),
        ),
        (
            "/api/user-roles/{id}",
            "delete",
            "api_user_roles_id_delete",
            ["204", "400", "401", "404", "412", "422", "428", "default"].as_slice(),
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
        for status in statuses.iter().filter(|status| !status.starts_with('2')) {
            assert_eq!(
                operation["responses"][status]["content"]["application/problem+json"]["schema"]["$ref"],
                "#/components/schemas/Problem",
                "{operation_id} {status}"
            );
        }
        assert!(
            operation["responses"]["204"].get("content").is_none(),
            "{operation_id}"
        );
    }
}

#[test]
fn the_assignment_creation_documents_its_request_headers_and_schemas() {
    let json = json_document();
    let operation = &json["paths"]["/api/user-roles"]["post"];

    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AssignUserRoleRequest"
    );
    assert_eq!(
        operation["responses"]["201"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/UserRole"
    );
    let headers: Vec<&str> = operation["responses"]["201"]["headers"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(headers, ["etag", "iam-policy-version", "location"]);
    let parameters = operation["parameters"].as_array().unwrap();
    assert_eq!(parameters.len(), 1);
    assert_eq!(parameters[0]["name"], "Idempotency-Key");
    assert_eq!(parameters[0]["in"], "header");
    let schemas = &json["components"]["schemas"];
    assert_eq!(
        schemas["AssignUserRoleRequest"]["additionalProperties"],
        false
    );
    assert_eq!(
        schemas["AssignUserRoleRequest"]["required"],
        json!(["subject", "roleId", "scope"])
    );
    assert_eq!(
        schemas["AssignmentSubject"]["required"],
        json!(["kind", "id"])
    );
    assert!(
        schemas["UserRolePage"]["properties"]
            .get("nextCursor")
            .is_some()
    );
}

#[test]
fn the_assignment_update_and_revocation_document_their_versioning_headers_and_schemas() {
    let json = json_document();
    let patch = &json["paths"]["/api/user-roles/{id}"]["patch"];
    let delete = &json["paths"]["/api/user-roles/{id}"]["delete"];

    assert_eq!(
        patch["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/UpdateUserRoleRequest"
    );
    assert_eq!(
        patch["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/UserRole"
    );
    assert!(delete.get("requestBody").is_none());
    for operation in [patch, delete] {
        let mut names: Vec<&str> = operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|parameter| parameter["name"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["Idempotency-Key", "If-Match", "id"]);
    }
    let schema = &json["components"]["schemas"]["UpdateUserRoleRequest"];
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["expiresAt"]));
}

#[test]
fn the_assignment_list_documents_its_query_parameters() {
    let json = json_document();
    let operation = &json["paths"]["/api/user-roles"]["get"];

    let mut names: Vec<&str> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|parameter| parameter["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "after",
            "includeExpired",
            "limit",
            "projectId",
            "roleId",
            "subjectId",
            "subjectKind"
        ]
    );
    assert_eq!(
        json["paths"]["/api/user-roles/{id}"]["get"]["parameters"][0]["in"],
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
fn defines_exactly_the_documented_schemas() {
    let json = json_document();
    let schemas = json["components"]["schemas"].as_object().unwrap();

    let names: Vec<&str> = schemas.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "AssignUserRoleRequest",
            "AssignmentScope",
            "AssignmentSubject",
            "CoordinateFlags",
            "CreateExampleApiResourceRequest",
            "CreateGraphQlPermissionsRequest",
            "CreateRoleRequest",
            "DeletedRole",
            "DependencyFailure",
            "ExampleApiResource",
            "FlagDowngrade",
            "GraphQlPermissionsActivation",
            "GraphQlSpec",
            "GraphQlSpecDiff",
            "GraphQlSpecPage",
            "GraphQlSpecSummary",
            "KeyRename",
            "LoadGraphQlSpecRequest",
            "LoadOpenApiSpecRequest",
            "OpenApiSpec",
            "OpenApiSpecDiff",
            "OpenApiSpecPage",
            "OpenApiSpecSummary",
            "OperationFlagDowngrade",
            "OperationFlags",
            "OperationWildcardGain",
            "Problem",
            "RemovedGrant",
            "RemovedOperationGrant",
            "Role",
            "RolePage",
            "TokenResolution",
            "TokenResolutionRequest",
            "UpdateRoleRequest",
            "UpdateUserRoleRequest",
            "UserRole",
            "UserRolePage",
            "Violation",
            "WildcardGain",
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
