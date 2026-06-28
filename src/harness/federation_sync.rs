// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(test)]
pub(crate) fn trusted_two_node_mesh()
-> Result<ramflux_sync::FederationMesh, Box<dyn std::error::Error>> {
    let mut mesh = ramflux_sync::FederationMesh::new();
    mesh.register_node("node_a.example", "https://node-a.example");
    mesh.register_node("node_b.example", "https://node-b.example");
    mesh.establish_trusted_link("node_a.example", "node_b.example")?;
    Ok(mesh)
}

#[cfg(test)]
pub(crate) fn trusted_three_node_mesh()
-> Result<ramflux_sync::FederationMesh, Box<dyn std::error::Error>> {
    let mut mesh = trusted_two_node_mesh()?;
    mesh.register_node("node_c.example", "https://node-c.example");
    mesh.establish_trusted_link("node_a.example", "node_c.example")?;
    mesh.establish_trusted_link("node_b.example", "node_c.example")?;
    Ok(mesh)
}
