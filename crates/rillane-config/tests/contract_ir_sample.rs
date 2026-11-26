//! IR 契约样本（RIL-083）：`contracts/schema_v1/ir_sample_v1.yaml` 是
//! 「老配置仍可解析」的活样本——只消费稳定核心块（control/telemetry/
//! ingress/egress/routing），其 IR 投影以 **subset 面**（必需键 + 类型）
//! 钉在 `ir_face_v1.json`：实际面多出键不失败（配置增量演进零差异
//! 纪律），缺键 / 改名 / 类型漂移在本门具名失败。
//!
//! 另钉 IR 往返稳定（IR → JSON Value → IR 恒等）——serde 投影漂移
//! （自定义 Serialize 改动）同门可查。

use rillane_config::RillaneConfig;
use serde_json::Value;

/// 相对仓库根的契约样本路径（测试运行于 target/ 之下）
fn repo_root(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn load_sample() -> RillaneConfig {
    let path = repo_root("contracts/schema_v1/ir_sample_v1.yaml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取契约样本 {}: {e}", path.display()));
    RillaneConfig::from_str(&raw, None)
        .unwrap_or_else(|e| panic!("契约样本解析失败（样本本身必须恒合法）: {e}"))
}

fn load_face() -> Value {
    let path = repo_root("contracts/schema_v1/ir_face_v1.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取 IR 面 {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("IR 面 JSON 解析失败: {e}"))
}

/// serde_json 值类型词表 → 实测类型判定（number 不分整浮——线格式上
/// JSON number 无整浮之别，消费方按字段语义解读）
fn type_matches(actual: &Value, declared: &str) -> bool {
    match declared {
        "object" => actual.is_object(),
        "array" => actual.is_array(),
        "string" => actual.is_string(),
        "boolean" => actual.is_boolean(),
        "number" => actual.is_number(),
        "null" => actual.is_null(),
        compound if compound.contains('|') => {
            compound.split('|').any(|t| type_matches(actual, t.trim()))
        }
        other => panic!("IR 面类型词表外声明「{other}」（face 文件自身写错）"),
    }
}

/// 单个 subset 面：必需键在场且类型相符；实际面多出键不失败。
/// face 文件里 `path` 仅作文档（导航由测试代码显式执行，防隐式求值歧义）。
fn assert_subset_face(actual: &Value, face: &Value, face_id: &str) {
    let keys = face["keys"]
        .as_object()
        .unwrap_or_else(|| panic!("面 {face_id} 缺 keys 对象"));
    let obj = actual
        .as_object()
        .unwrap_or_else(|| panic!("面 {face_id}：实际投影不是对象（IR 结构漂移）"));
    for (k, declared) in keys {
        let declared = declared.as_str().expect("类型声明是字符串");
        match obj.get(k) {
            None => panic!(
                "IR 面漂移 @ {face_id}.{k}：必需键缺失（改名/删除=破坏兼容，须过 schema_v2 事务）"
            ),
            Some(v) if !type_matches(v, declared) => {
                panic!("IR 面漂移 @ {face_id}.{k}：类型漂移，声明 {declared}，实际 {v}")
            }
            Some(_) => {}
        }
    }
}

#[test]
fn ir_sample_projects_required_face() {
    let cfg = load_sample();
    let ir = serde_json::to_value(&cfg).expect("IR 可序列化投影");
    let face = load_face();
    assert_eq!(face["schema_version"], serde_json::json!(1u32));
    for face_id in [
        "ir_root",
        "control",
        "telemetry",
        "ingress_entry",
        "egress_entry",
        "routing",
        "rule_entry",
        "match_entry",
    ] {
        let f = &face["faces"][face_id];
        assert!(f.is_object(), "面 {face_id} 应在 face 文件中登记");
        let path = f["path"].as_str().unwrap_or("$");
        let actual = path
            .trim_start_matches('$')
            .split('.')
            .filter(|seg| !seg.is_empty())
            .fold(ir.clone(), |acc, seg| match seg.split_once('[') {
                Some((key, idx)) => {
                    let idx: usize = idx
                        .trim_end_matches(']')
                        .parse()
                        .unwrap_or_else(|e| panic!("面 {face_id} path 段 {seg} 下标非法: {e}"));
                    acc[key][idx].clone()
                }
                None => acc[seg].clone(),
            });
        assert_subset_face(&actual, f, face_id);
    }
}

#[test]
fn ir_sample_roundtrips_through_json_value() {
    let cfg = load_sample();
    let ir = serde_json::to_value(&cfg).expect("IR 可序列化投影");
    let text = serde_json::to_string(&ir).expect("IR 投影可文本化");
    let back: Value = serde_json::from_str(&text).expect("JSON 文本可回读");
    assert_eq!(
        ir, back,
        "IR 投影经 JSON 文本往返必须恒等（serde 自定义投影不得依赖 Map 序列外的隐性状态）"
    );
}

/// 样本形态自证：样本确实未消费任何后期可选块（可选块缺席 = 缺键而非
/// null 占位——subset 面对缺席键的唯一合法形态）。若未来某核心块变为
/// 可选并从样本中缺席，此测试点名提醒同步 face 文件。
#[test]
fn sample_consumes_only_core_blocks() {
    let cfg = load_sample();
    let ir = serde_json::to_value(&cfg).expect("IR 投影");
    assert_eq!(ir["ingress"][0]["type"], "socks5", "样本入口 socks5");
    assert_eq!(ir["egress"][0]["type"], "direct", "样本出口 direct");
    assert_eq!(
        ir["routing"]["rules"][0]["matches"][0]["type"], "domain_suffix",
        "样本规则域名后缀条件"
    );
}

/// 对账器自证：把 face 里一个键的类型声明改错，本门必须失败且点名。
#[test]
#[should_panic(expected = "IR 面漂移 @ control.api_bind：类型漂移")]
fn comparator_bites_on_type_drift() {
    let cfg = load_sample();
    let ir = serde_json::to_value(&cfg).expect("IR 投影");
    let mut face = load_face();
    face["faces"]["control"]["keys"]["api_bind"] = serde_json::json!("array");
    assert_subset_face(&ir["control"], &face["faces"]["control"], "control");
}

#[test]
#[should_panic(expected = "IR 面漂移 @ control.missing_key：必需键缺失")]
fn comparator_bites_on_missing_key() {
    let cfg = load_sample();
    let ir = serde_json::to_value(&cfg).expect("IR 投影");
    let mut face = load_face();
    face["faces"]["control"]["keys"]["missing_key"] = serde_json::json!("string");
    assert_subset_face(&ir["control"], &face["faces"]["control"], "control");
}
