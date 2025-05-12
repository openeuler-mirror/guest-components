// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
struct ResourceLocation {
    vendor: Option<String>,
    path: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct GetResourceRequest {
    uuid: String,
    challenge: Option<String>,
    ima: Option<bool>,
    policy_id: Option<Vec<String>>,
    resource: ResourceLocation,
}

pub async fn decrypt_image_layer_annotation(
    secgear_aa_addr: &str,
    key_path: &str,
) -> Result<Vec<u8>> {
    let mut parts = key_path.splitn(2, '/');
    let first = parts.next().unwrap_or("").to_string();
    let second = parts.next().unwrap_or("").to_string();

    let request = GetResourceRequest {
        uuid: "xxx".to_string(),
        challenge: None,
        ima: None,
        policy_id: None,
        resource: ResourceLocation {
            vendor: Some(first),
            path: second,
        },
    };

    let client = reqwest::Client::new();

    let response = client
        .get(format!("http://{}/resource/storage", secgear_aa_addr))
        .json(&request)
        .send()
        .await?;

    match response.status() {
        reqwest::StatusCode::OK => {
            let priv_opts =
                String::from_utf8_lossy(&response.bytes().await.unwrap().to_vec()).into_owned();
            let priv_opts = priv_opts
                .strip_prefix('"')
                .unwrap_or(&priv_opts)
                .strip_suffix('"')
                .unwrap_or(&priv_opts);

            return Ok(general_purpose::STANDARD.decode(&priv_opts).unwrap());
        }
        status => {
            bail!("secgear get decrypt key failed: {}", status)
        }
    }
}
