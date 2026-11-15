//! 代际契约验收（RIL-003）：失败候选不覆盖成功代际；旧代际可被存活
//! 会话引用；同内容发布幂等。纯数据结构与校验，零网络零 OS 依赖。

use std::sync::Arc;

use rillane_config::{
    digest_parts, GenerationEdge, GenerationObject, GenerationStore, ObjectId, ObjectKind,
    RuntimeGeneration, SourceId, CODE_GENERATION_CYCLE, CODE_GENERATION_DANGLING,
};

fn source(name: &str) -> SourceId {
    SourceId::new(name).unwrap()
}

fn obj(source_name: &str, local_id: &str, kind: ObjectKind) -> GenerationObject {
    GenerationObject {
        id: ObjectId::new(source(source_name), local_id),
        kind,
        content_hash: digest_parts(&[source_name, local_id, "v1"]),
    }
}

fn edge(from: &str, to: &str) -> GenerationEdge {
    GenerationEdge {
        from: ObjectId::new(source("sub"), from),
        to: ObjectId::new(source("sub"), to),
    }
}

/// g1 -> n1 的合法候选
fn candidate_v1() -> (Vec<GenerationObject>, Vec<GenerationEdge>) {
    (
        vec![
            obj("sub", "n1", ObjectKind::Node),
            obj("sub", "g1", ObjectKind::Group),
        ],
        vec![edge("g1", "n1")],
    )
}

/// 内容升级版候选（n1 内容变化）
fn candidate_v2() -> (Vec<GenerationObject>, Vec<GenerationEdge>) {
    let mut objects = vec![
        obj("sub", "n1", ObjectKind::Node),
        obj("sub", "g1", ObjectKind::Group),
    ];
    objects[0].content_hash = digest_parts(&["sub", "n1", "v2"]);
    (objects, vec![edge("g1", "n1")])
}

#[test]
fn failed_candidate_keeps_published_generation() {
    let mut store = GenerationStore::new();
    let gen1 = store
        .publish(candidate_v1().0, candidate_v1().1)
        .expect("合法候选必须发布成功");
    let gen1_id = gen1.generation_id().to_string();

    // 失败候选一：悬空引用——必须拒绝且发布位不动
    let objects = vec![
        obj("sub", "n1", ObjectKind::Node),
        obj("sub", "g1", ObjectKind::Group),
    ];
    let err = store
        .publish(objects, vec![edge("g1", "ghost")])
        .expect_err("悬空引用必须拒绝");
    assert_eq!(err.code(), CODE_GENERATION_DANGLING);

    // 失败候选二：循环引用——同样拒绝且发布位不动
    let objects = vec![
        obj("sub", "g1", ObjectKind::Group),
        obj("sub", "g2", ObjectKind::Group),
    ];
    let err = store
        .publish(objects, vec![edge("g1", "g2"), edge("g2", "g1")])
        .expect_err("循环引用必须拒绝");
    assert_eq!(err.code(), CODE_GENERATION_CYCLE);

    // 发布位仍是 gen1：身份不变、内容完整可用
    let published = store.published().expect("发布位必须保持");
    assert_eq!(published.generation_id(), gen1_id);
    assert!(published.get(&ObjectId::new(source("sub"), "n1")).is_some());
}

#[test]
fn pinned_old_generation_survives_new_publish() {
    let mut store = GenerationStore::new();
    let gen1: std::sync::Arc<RuntimeGeneration> =
        store.publish(candidate_v1().0, candidate_v1().1).unwrap();
    let gen1_id = gen1.generation_id().to_string();

    // 发布 v2：发布位顶替
    let gen2 = store.publish(candidate_v2().0, candidate_v2().1).unwrap();
    assert_ne!(
        gen1.generation_id(),
        gen2.generation_id(),
        "内容变化必产生新代际"
    );
    assert_eq!(
        store.published().unwrap().generation_id(),
        gen2.generation_id()
    );

    // 旧代际句柄（模拟存活会话持有的 pin）仍然完整可用：不可变、
    // 对象与引用边保持 v1 内容
    assert_eq!(gen1.generation_id(), gen1_id);
    assert_eq!(gen1.len(), 2);
    let n1 = gen1
        .get(&ObjectId::new(source("sub"), "n1"))
        .expect("旧代际对象必须可查");
    assert_eq!(n1.content_hash, digest_parts(&["sub", "n1", "v1"]));
    assert_eq!(gen1.edges().count(), 1);

    // v2 的 n1 是新内容，与旧代际互不干扰
    let n1_v2 = gen2.get(&ObjectId::new(source("sub"), "n1")).unwrap();
    assert_eq!(n1_v2.content_hash, digest_parts(&["sub", "n1", "v2"]));
}

#[test]
fn same_content_publish_is_idempotent() {
    let mut store = GenerationStore::new();
    let gen1 = store.publish(candidate_v1().0, candidate_v1().1).unwrap();
    let gen1b = store.publish(candidate_v1().0, candidate_v1().1).unwrap();
    assert_eq!(
        Arc::as_ptr(&gen1),
        Arc::as_ptr(&gen1b),
        "同内容重复发布返回现有代际，不产生假新版本"
    );

    // 内容升级后再回到 v1 内容——摘要身份相同，仍是同一代际
    store.publish(candidate_v2().0, candidate_v2().1).unwrap();
    let gen1c = store.publish(candidate_v1().0, candidate_v1().1).unwrap();
    assert_eq!(
        gen1c.generation_id(),
        gen1.generation_id(),
        "内容寻址身份：回到同内容即同代际"
    );
}

#[test]
fn generation_roundtrips_through_serde() {
    let gen = RuntimeGeneration::build(candidate_v1().0, candidate_v1().1).unwrap();
    let json = serde_json::to_string(&gen).expect("可序列化");
    let back: RuntimeGeneration = serde_json::from_str(&json).expect("可反序列化");
    assert_eq!(back, gen, "round-trip 保持代际（含内容身份）");
    assert_eq!(back.generation_id(), gen.generation_id());
}
