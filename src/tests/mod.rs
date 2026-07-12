// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;
use ramflux_protocol::{
    Ack, Cursor, Envelope, FIXTURE_OBJECTS, Nack, NackReason, SignedRequest,
    fixture_canonical_path, fixture_hash_path, fixture_invalid_signature_path, fixture_json_path,
    fixture_replay_path, fixture_sig_path, hash_hex, parse_fixture_value, signed_value,
};
use ramflux_storage::{
    AccountDb, AccountDbKey, AccountIndex, EncryptionMode, EventStore, ProjectionStore,
};
use ramflux_transport::{
    BackendKind, GrpcH2Backend, HttpsJsonBackend, QuicQuinnBackend, TransportBackend,
};
use std::collections::BTreeSet;

#[path = "federation.rs"]
mod federation;
#[path = "fixtures_smoke.rs"]
mod fixtures_smoke;
#[path = "groups_bots.rs"]
mod groups_bots;
#[path = "identity_sdk_a.rs"]
mod identity_sdk_a;
#[path = "identity_sdk_b.rs"]
mod identity_sdk_b;
#[path = "local_support.rs"]
mod local_support;
pub(crate) use local_support::*;
#[path = "mcp_a2ui_webrtc.rs"]
mod mcp_a2ui_webrtc;
#[path = "messages.rs"]
mod messages;
#[path = "misc.rs"]
mod misc;
#[path = "mvp01_realnet.rs"]
mod mvp01_realnet;
#[path = "mvp10_coverage.rs"]
mod mvp10_coverage;
#[path = "mvp23_realnet.rs"]
mod mvp23_realnet;
#[path = "mvp45_realnet.rs"]
mod mvp45_realnet;
#[path = "mvp6_trust_abuse.rs"]
mod mvp6_trust_abuse;
#[path = "mvp7_compliance.rs"]
mod mvp7_compliance;
#[path = "mvp8_federation.rs"]
mod mvp8_federation;
#[path = "mvp9_messages.rs"]
mod mvp9_messages;
#[path = "mvp_s01_gateway_session.rs"]
mod mvp_s01_gateway_session;
#[path = "mvp_s02_sdk_session.rs"]
mod mvp_s02_sdk_session;
#[path = "mvp_s03_daemon_bus.rs"]
mod mvp_s03_daemon_bus;
#[path = "mvp_s04_rf_cli_x3dh.rs"]
mod mvp_s04_rf_cli_x3dh;
#[path = "mvp_s06_mcp_host.rs"]
mod mvp_s06_mcp_host;
#[path = "mvp_s07_group_sender_key.rs"]
mod mvp_s07_group_sender_key;
#[path = "mvp_s08_federation_dm.rs"]
mod mvp_s08_federation_dm;
#[path = "mvp_s09_friend_group.rs"]
mod mvp_s09_friend_group;
#[path = "mvp_s10_private_node.rs"]
mod mvp_s10_private_node;
#[path = "mvp_s11_double_ratchet.rs"]
mod mvp_s11_double_ratchet;
#[path = "mvp_s12_discovery.rs"]
mod mvp_s12_discovery;
#[path = "mvp_s13_push.rs"]
mod mvp_s13_push;
#[path = "mvp_s14_friend_block.rs"]
mod mvp_s14_friend_block;
#[path = "mvp_s15_object_call_bot.rs"]
mod mvp_s15_object_call_bot;
#[path = "mvp_s16_object_keys.rs"]
mod mvp_s16_object_keys;
#[path = "mvp_s17_a2ui.rs"]
mod mvp_s17_a2ui;
#[path = "mvp_s18_a2i_delivery.rs"]
mod mvp_s18_a2i_delivery;
#[path = "mvp_s19_prod_register.rs"]
mod mvp_s19_prod_register;
#[path = "mvp_s20_daemon_restart.rs"]
mod mvp_s20_daemon_restart;
#[path = "mvp_s21_group_read.rs"]
mod mvp_s21_group_read;
#[path = "mvp_s22_peering.rs"]
mod mvp_s22_peering;
#[path = "mvp_s23_cross_node_group.rs"]
mod mvp_s23_cross_node_group;
#[path = "mvp_s24_out_of_order.rs"]
mod mvp_s24_out_of_order;
#[path = "mvp_s25_social_recovery.rs"]
mod mvp_s25_social_recovery;
#[path = "mvp_s30_account_backup.rs"]
mod mvp_s30_account_backup;
#[path = "mvp_s31_group_governance.rs"]
mod mvp_s31_group_governance;
#[path = "mvp_s32_dm_receipt_delete.rs"]
mod mvp_s32_dm_receipt_delete;
#[path = "mvp_s33_contact_safety_number.rs"]
mod mvp_s33_contact_safety_number;
#[path = "mvp_s34_tui_live_daemon.rs"]
mod mvp_s34_tui_live_daemon;
#[path = "mvp_s35_multi_device.rs"]
mod mvp_s35_multi_device;
#[path = "mvp_s36_tui_remote_app_approval.rs"]
mod mvp_s36_tui_remote_app_approval;
#[path = "mvp_s37_tui_compose_mode.rs"]
mod mvp_s37_tui_compose_mode;
#[path = "mvp_s38_standing_auto_approval.rs"]
mod mvp_s38_standing_auto_approval;
#[path = "mvp_s39_device_aware_safety_number.rs"]
mod mvp_s39_device_aware_safety_number;
#[path = "mvp_s39_gateway_resume.rs"]
mod mvp_s39_gateway_resume;
#[path = "mvp_s40_object_resume.rs"]
mod mvp_s40_object_resume;
#[path = "mvp_s41_dm_attachment.rs"]
mod mvp_s41_dm_attachment;
#[path = "mvp_s42_tui_object_attachment.rs"]
mod mvp_s42_tui_object_attachment;
#[path = "mvp_s43_receipt_network.rs"]
mod mvp_s43_receipt_network;
#[path = "mvp_s44_group_control_roles.rs"]
mod mvp_s44_group_control_roles;
#[path = "mvp_s45_group_control_rekey.rs"]
mod mvp_s45_group_control_rekey;
#[path = "mvp_s46_group_invite_accept.rs"]
mod mvp_s46_group_invite_accept;
#[path = "mvp_s47_restore_device_rejoin.rs"]
mod mvp_s47_restore_device_rejoin;
#[path = "mvp_s48_own_device_sync.rs"]
mod mvp_s48_own_device_sync;
#[path = "mvp_s49_tui_account_contact.rs"]
mod mvp_s49_tui_account_contact;
#[path = "mvp_s50_cross_gateway.rs"]
mod mvp_s50_cross_gateway;
#[path = "mvp_s51_home_node_migration_forward.rs"]
mod mvp_s51_home_node_migration_forward;
#[path = "mvp_s52_media_relay.rs"]
mod mvp_s52_media_relay;
#[path = "mvp_s53_quic_ingress_perf.rs"]
mod mvp_s53_quic_ingress_perf;
#[path = "mvp_s54_object_v3_runtime.rs"]
mod mvp_s54_object_v3_runtime;
#[path = "mvp_s55_object_v3_public_sdk.rs"]
mod mvp_s55_object_v3_public_sdk;
#[path = "mvp_s56_object_v3_grantee.rs"]
mod mvp_s56_object_v3_grantee;
#[path = "mvp_s58_trust_snapshot_lifecycle.rs"]
mod mvp_s58_trust_snapshot_lifecycle;
#[path = "mvp_s59_trust_root_cert_rotation.rs"]
mod mvp_s59_trust_root_cert_rotation;
#[path = "mvp_s60_gateway_attestation_rotation.rs"]
mod mvp_s60_gateway_attestation_rotation;
#[path = "mvp_s61_provider_keyring_rotation.rs"]
mod mvp_s61_provider_keyring_rotation;
#[path = "mvp_s62_object_v3_quic_fault.rs"]
mod mvp_s62_object_v3_quic_fault;
#[path = "mvp_s63_rfd_midflight_crash.rs"]
mod mvp_s63_rfd_midflight_crash;
#[path = "objects.rs"]
mod objects;
#[path = "transport_node_store.rs"]
mod transport_node_store;
