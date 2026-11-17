//! 来源与诊断契约验收（RIL-002）：同名跨来源对象无冲突、诊断定位对象
//! 与字段、删除与改名语义明确。纯契约测试，零网络零 OS 依赖。

use rillane_config::{
    derive_local_id, CompatibilityDiagnostic, ObjectCatalog, ObjectId, ObjectKind,
    SourceContractError, SourceId, SourceLocation, SourceObject, SourceSnapshot, CODE_COMPAT_LOSSY,
    CODE_COMPAT_UNSUPPORTED, CODE_SOURCE_ID_INVALID, CODE_SOURCE_MISMATCH,
};

/// 构造来源内对象：local_id 由内容身份派生（Clash proxies 无上游 ID）
fn node(source: SourceId, pointer: &str, display_name: &str, identity: &[&str]) -> SourceObject {
    SourceObject {
        id: ObjectId::new(source.clone(), derive_local_id(identity)),
        kind: ObjectKind::Node,
        display_name: display_name.to_string(),
        location: SourceLocation::new(source, pointer),
    }
}

fn snapshot(source: SourceId, objects: Vec<SourceObject>) -> SourceSnapshot {
    SourceSnapshot {
        source,
        content_hash: "deadbeef".to_string(),
        parser_version: 1,
        fetched_at_unix_ms: 0,
        objects,
    }
}

#[test]
fn same_display_name_across_sources_no_conflict() {
    // 验收：同名跨来源对象无冲突——「香港 01」在两个来源各有一份
    let src_a = SourceId::new("airport-a").unwrap();
    let src_b = SourceId::new("airport-b").unwrap();
    let name = "香港 01";

    let obj_a = node(
        src_a.clone(),
        "proxies/0",
        name,
        &["vmess", "1.2.3.4", "443"],
    );
    let obj_b = node(
        src_b.clone(),
        "proxies/0",
        name,
        &["vmess", "5.6.7.8", "443"],
    );
    let obj_a_id = obj_a.id.clone();
    let obj_b_id = obj_b.id.clone();

    let mut catalog = ObjectCatalog::new();
    catalog
        .merge_snapshot(&snapshot(src_a, vec![obj_a]))
        .expect("来源 A 并入目录");
    catalog
        .merge_snapshot(&snapshot(src_b, vec![obj_b]))
        .expect("同名跨来源对象必须共存，不冲突");

    assert_eq!(catalog.len(), 2, "同名两对象都在目录中");
    assert_eq!(
        catalog.by_display_name(name).len(),
        2,
        "按名查找可区分地返回两个"
    );
    assert!(catalog.get(&obj_a_id).is_some());
    assert!(catalog.get(&obj_b_id).is_some());
    assert_ne!(
        obj_a_id, obj_b_id,
        "身份 = (来源, local_id)，来源不同即不同"
    );
}

#[test]
fn same_source_duplicate_local_id_rejected_not_merged() {
    // 同来源内两条同内容身份的对象：显式报错，不静默合并
    let src = SourceId::new("airport-a").unwrap();
    let obj = node(src.clone(), "proxies/0", "A", &["vmess", "1.2.3.4", "443"]);
    let dup = node(src.clone(), "proxies/1", "B", &["vmess", "1.2.3.4", "443"]);
    // 同快照内两个对象同 local_id：目录按对象逐个插入，第二个触发诊断
    let snap = snapshot(src.clone(), vec![obj.clone(), dup.clone()]);
    let mut catalog = ObjectCatalog::new();
    let err = catalog
        .merge_snapshot(&snap)
        .expect_err("同来源同 local_id 必须拒绝");
    assert_eq!(err.code(), CODE_SOURCE_ID_INVALID);
    assert_eq!(catalog.len(), 1, "失败前已插入的不回滚，由调用方整批替换");
    assert!(matches!(err, SourceContractError::InvalidSourceId { .. }));
}

#[test]
fn diagnostic_locates_object_and_field() {
    // 验收：诊断能定位对象与字段——对象 ID + 来源位置指针 + 字段路径
    let src = SourceId::new("airport-a").unwrap();
    let location = SourceLocation::new(src.clone(), "proxies/3");
    let object = ObjectId::new(src, derive_local_id(&["vless", "1.2.3.4", "443"]));

    // 不支持：对象级
    let unsupported = CompatibilityDiagnostic::unsupported(
        Some(object.clone()),
        location.clone(),
        "relay 链式组不支持",
    );
    assert_eq!(unsupported.code, CODE_COMPAT_UNSUPPORTED);
    assert_eq!(unsupported.location.pointer, "proxies/3");
    assert_eq!(unsupported.object.as_ref(), Some(&object));

    // 有损：字段级（位置可链式下钻到字段）
    let field_location = location.join("ws-opts.headers.Host");
    let lossy = CompatibilityDiagnostic::lossy(
        Some(object),
        field_location,
        Some("host".into()),
        "ws host 改写为固定值",
    );
    assert_eq!(lossy.code, CODE_COMPAT_LOSSY);
    assert_eq!(
        lossy.location.pointer, "proxies/3/ws-opts.headers.Host",
        "诊断定位到具体字段"
    );
    assert_eq!(lossy.field.as_deref(), Some("host"));
}

#[test]
fn delete_and_rename_semantics_explicit() {
    // 验收：删除与改名语义明确——diff 显式给出 removed/renamed/added
    let src = SourceId::new("airport-a").unwrap();

    // A: 保留不变；B: 改名（同 server/port 身份，新显示名）；C: 删除；D: 新增
    let v1 = snapshot(
        src.clone(),
        vec![
            node(src.clone(), "proxies/0", "A", &["vmess", "10.0.0.1", "443"]),
            node(
                src.clone(),
                "proxies/1",
                "B-old",
                &["vmess", "10.0.0.2", "443"],
            ),
            node(src.clone(), "proxies/2", "C", &["vmess", "10.0.0.3", "443"]),
        ],
    );
    let v2 = snapshot(
        src.clone(),
        vec![
            node(src.clone(), "proxies/0", "A", &["vmess", "10.0.0.1", "443"]),
            node(
                src.clone(),
                "proxies/1",
                "B-new",
                &["vmess", "10.0.0.2", "443"],
            ),
            node(src.clone(), "proxies/3", "D", &["vmess", "10.0.0.4", "443"]),
        ],
    );

    let diff = v1.diff(&v2).expect("同来源 diff 必须成功");
    assert_eq!(diff.unchanged, 1, "A 未变");
    assert_eq!(diff.renamed.len(), 1, "B 是改名，不是删+增");
    assert_eq!(diff.renamed[0].old_name, "B-old");
    assert_eq!(diff.renamed[0].new_name, "B-new");
    assert_eq!(diff.removed.len(), 1, "C 显式删除");
    assert_eq!(
        diff.removed[0].local_id,
        derive_local_id(&["vmess", "10.0.0.3", "443"])
    );
    assert_eq!(diff.added.len(), 1, "D 显式新增");
    assert_eq!(
        diff.added[0].local_id,
        derive_local_id(&["vmess", "10.0.0.4", "443"])
    );

    // 同显示名、不同身份 = 两个对象（增+删），不算改名——不靠名字猜身份
    let v3 = snapshot(
        src.clone(),
        vec![node(
            src.clone(),
            "proxies/9",
            "A",
            &["vmess", "10.0.0.9", "443"],
        )],
    );
    let diff = v1.diff(&v3).expect("同来源 diff 必须成功");
    assert!(
        diff.renamed.is_empty(),
        "同名不同身份不得判为改名: {:?}",
        diff.renamed
    );
    assert_eq!(diff.removed.len(), 3);
    assert_eq!(diff.added.len(), 1);
}

#[test]
fn cross_source_diff_rejected_with_stable_code() {
    // diff 只在同一来源内进行：跨来源比较是契约错误
    let a = SourceId::new("airport-a").unwrap();
    let b = SourceId::new("airport-b").unwrap();
    let s1 = snapshot(a, vec![]);
    let s2 = snapshot(b, vec![]);
    let err = s1.diff(&s2).unwrap_err();
    assert_eq!(err.code(), CODE_SOURCE_MISMATCH);
    assert!(matches!(err, SourceContractError::SourceMismatch { .. }));
}

#[test]
fn snapshot_content_hash_is_content_addressed() {
    // 内容摘要：同内容同 hash，不同内容不同 hash（来源版本参与方）
    let h1 = SourceSnapshot::hash_content(b"proxies: []");
    let h1_again = SourceSnapshot::hash_content(b"proxies: []");
    let h2 = SourceSnapshot::hash_content(b"proxies: [x]");
    assert_eq!(h1, h1_again);
    assert_ne!(h1, h2);
    assert_eq!(h1.len(), 64, "SHA-256 十六进制 64 字符");
}
