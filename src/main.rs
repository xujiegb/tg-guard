use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rand::seq::SliceRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime},
};
use teloxide::{
    dispatching::UpdateHandler,
    dptree,
    prelude::*,
    requests::{HasPayload, Payload, Request},
    types::{
        CallbackQuery, ChatId, ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup, Message,
        MessageId, ParseMode, UserId,
    },
};
use tokio::sync::{broadcast, Mutex};
use tracing::{info, warn};

const CALLBACK_PREFIX: &str = "v";
const GROUP_SNAPSHOT_PREFIX: &str = "group_";
const GROUP_SNAPSHOT_SUFFIX: &str = ".json";
const TEMP_FILE_SUFFIX: &str = ".tmp";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PunishmentAction {
    Kick,
    Ban,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutoStartOpt {
    On,
    Off,
    Unspecified,
}

fn parse_autostart_arg(args: &[String]) -> AutoStartOpt {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--autostartbash" {
            if i + 1 < args.len() {
                match args[i + 1].as_str() {
                    "on" => return AutoStartOpt::On,
                    "off" => return AutoStartOpt::Off,
                    _ => return AutoStartOpt::Unspecified,
                }
            }
            return AutoStartOpt::Unspecified;
        }
        i += 1;
    }
    AutoStartOpt::Unspecified
}

fn systemd_user_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".config/systemd/user")
}

fn service_path() -> PathBuf {
    systemd_user_dir().join("tg-guard.service")
}

fn current_exec_command(args: &[String]) -> String {
    let exe = std::env::current_exe()
        .expect("cannot get current exe")
        .display()
        .to_string();

    let mut filtered: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--autostartbash" {
            i += 2;
            continue;
        }
        filtered.push(args[i].clone());
        i += 1;
    }

    let tail = if filtered.len() > 1 {
        filtered[1..].join(" ")
    } else {
        "".to_string()
    };

    if tail.is_empty() {
        format!("{}", exe)
    } else {
        format!("{} {}", exe, tail)
    }
}

fn enable_autostart(args: &[String]) -> Result<()> {
    let dir = systemd_user_dir();
    std::fs::create_dir_all(&dir)?;

    let exec_cmd = current_exec_command(args);

    let content = format!(
        r#"[Unit]
Description=tg-guard Telegram Guard Bot
After=network-online.target

[Service]
ExecStart={}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"#,
        exec_cmd
    );

    let path = service_path();
    std::fs::write(&path, content)?;

    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    let _ = Command::new("systemctl")
        .args(["--user", "enable", "tg-guard.service"])
        .status();

    let _ = Command::new("systemctl")
        .args(["--user", "start", "tg-guard.service"])
        .status();

    info!("autostart enabled (systemd --user)");
    Ok(())
}

fn disable_autostart() -> Result<()> {
    let path = service_path();

    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", "tg-guard.service"])
        .status();

    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    if path.exists() {
        std::fs::remove_file(path)?;
    }

    info!("autostart disabled and cleaned");
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistVerify {
    chat_id: i64,
    user_id: u64,
    question_id: String,
    shuffled_options: Vec<String>,
    correct_index: usize,
    attempts_left: u32,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistWarn {
    chat_id: i64,
    user_id: u64,
    rule_name: String,
    timestamps: Vec<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistSnapshot {
    verify: Vec<PersistVerify>,
    warns: Vec<PersistWarn>,
    saved_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Clone)]
struct Config {
    bot: BotConfig,
    runtime: RuntimeConfig,
    groups: Vec<GroupConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct BotConfig {
    token: String,
    polling_timeout_secs: Option<u64>,
    log_level: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct SnapshotCleanupCfg {
    enable_daily_cleanup: Option<bool>,
    retention_days: Option<i64>,
    daily_cleanup_at: Option<String>,
    enable_disk_guard: Option<bool>,
    disk_free_percent_low: Option<u8>,
    delete_oldest_fraction: Option<f64>,
    filename_prefix: Option<String>,
    filename_suffix: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct RuntimeConfig {
    data_dir: Option<String>,
    merge_group_notice: Option<bool>,
    merge_group_notice_max_names: Option<usize>,
    merge_group_notice_interval_secs: Option<u64>,

    snapshots: Option<SnapshotCleanupCfg>,
}

#[derive(Debug, Deserialize, Clone)]
struct GroupConfig {
    name: String,
    chat_id: i64,
    ignore_admins: Option<bool>,

    // ✅ 可有可无：不写就 None（不执行加群验证）
    #[serde(default)]
    join_verification: Option<JoinVerification>,

    // ✅ 可有可无：不写就当 []
    #[serde(default)]
    auto_replies: Vec<TextRule>,
    #[serde(default)]
    warnings: Vec<WarningRule>,
    #[serde(default)]
    kicks: Vec<KickRule>,

    // ✅ 可有可无：不写就 None（不执行群命令）
    #[serde(default)]
    commands: Option<Commands>,
}

#[derive(Debug, Deserialize, Clone)]
struct Commands {
    enabled: Option<bool>,
    admin_only: Option<bool>,
    prefix: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct JoinVerification {
    enabled: bool,
    restrict: PermissionsCfg,
    questions: Vec<Question>,
    timeout_secs: u64,
    max_attempts: u32,
    group_notice_template: String,
    dm_intro: String,
    on_fail: FailAction,
    on_pass: PassAction,
}

#[derive(Debug, Deserialize, Clone)]
struct PermissionsCfg {
    can_send_messages: bool,
    can_send_media_messages: bool,
    can_send_polls: bool,
    can_send_other_messages: bool,
    can_add_web_page_previews: bool,
    can_change_info: bool,
    can_invite_users: bool,
    can_pin_messages: bool,
}

#[derive(Debug, Deserialize, Clone)]
struct Question {
    id: String,
    prompt: String,
    options: Vec<String>,
    answer: String,
}

#[derive(Debug, Deserialize, Clone)]
struct FailAction {
    action: PunishmentAction,
    ban_minutes: Option<i64>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct PassAction {
    welcome_dm: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct MatchCond {
    any_keywords: Option<Vec<String>>,
    all_keywords: Option<Vec<String>>,
    regex: Option<Vec<String>>,
    case_insensitive: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
struct TextRule {
    name: String,
    #[serde(rename = "match")]
    cond: MatchCond,
    reply: String,
}

#[derive(Debug, Deserialize, Clone)]
struct WarningRule {
    name: String,
    #[serde(rename = "match")]
    cond: MatchCond,
    warn_message: String,
    window_minutes: i64,
    limit: u32,
    on_limit: LimitAction,
}

#[derive(Debug, Deserialize, Clone)]
struct LimitAction {
    action: PunishmentAction,
    ban_minutes: Option<i64>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct KickRule {
    name: String,
    #[serde(rename = "match")]
    cond: MatchCond,
    action: PunishmentAction,
    ban_minutes: Option<i64>,
    delete_message: Option<bool>,
    reason: Option<String>,
}

#[derive(Clone)]
struct AppState {
    groups: HashMap<ChatId, Arc<GroupState>>,
    bot_username: String,
    merged_notice: Arc<Mutex<HashMap<ChatId, MergedNoticeBuffer>>>,
    runtime: RuntimeConfig,
    data_dir: String,
}

struct GroupState {
    cfg: GroupConfig,
    admins: DashMap<UserId, bool>,
    verify: DashMap<(ChatId, UserId), VerifySession>,
    warns: DashMap<(ChatId, UserId, String), Vec<DateTime<Utc>>>,
    rule_regex: DashMap<String, Vec<Regex>>,
}

#[derive(Clone)]
struct VerifySession {
    question_id: String,
    shuffled_options: Vec<String>,
    correct_index: usize,
    attempts_left: u32,
    expires_at: DateTime<Utc>,
}

struct MergedNoticeBuffer {
    users: Vec<(UserId, String)>,
    last_sent: DateTime<Utc>,
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read config: {}", path.display()))?;
    let cfg: Config = serde_yaml::from_str(&text).context("parse yaml")?;
    Ok(cfg)
}

fn validate_config(cfg: &Config) -> Result<()> {
    let mut seen_chat = std::collections::HashMap::<i64, String>::new();
    for g in &cfg.groups {
        if let Some(prev) = seen_chat.insert(g.chat_id, g.name.clone()) {
            return Err(anyhow!(
                "duplicate chat_id {} found in groups: '{}' and '{}'",
                g.chat_id,
                prev,
                g.name
            ));
        }

        // ✅ join_verification 可选：只有存在且 enabled 才校验
        if let Some(jv) = &g.join_verification {
            if jv.enabled {
                if jv.timeout_secs < 5 || jv.timeout_secs > 24 * 3600 {
                    return Err(anyhow!(
                        "group '{}' timeout_secs={} out of range (5..=86400)",
                        g.name,
                        jv.timeout_secs
                    ));
                }
                if jv.questions.is_empty() {
                    return Err(anyhow!(
                        "group '{}' join_verification.questions is empty but enabled=true",
                        g.name
                    ));
                }
                for q in &jv.questions {
                    if q.options.is_empty() {
                        return Err(anyhow!(
                            "group '{}' question '{}' options is empty",
                            g.name,
                            q.id
                        ));
                    }
                    if !q.options.iter().any(|x| x == &q.answer) {
                        return Err(anyhow!(
                            "group '{}' question '{}' answer not found in options (answer='{}')",
                            g.name,
                            q.id,
                            q.answer
                        ));
                    }
                }
            }
        }

        for r in &g.warnings {
            if r.window_minutes <= 0 {
                return Err(anyhow!(
                    "group '{}' warning rule '{}' window_minutes must be > 0",
                    g.name,
                    r.name
                ));
            }
            if r.limit == 0 {
                return Err(anyhow!(
                    "group '{}' warning rule '{}' limit must be > 0",
                    g.name,
                    r.name
                ));
            }
        }
    }
    Ok(())
}

fn match_text(cond: &MatchCond, text: &str, compiled: &[Regex]) -> bool {
    let mut t = text.to_string();
    let ci = cond.case_insensitive.unwrap_or(true);
    if ci {
        t = t.to_lowercase();
    }
    let any = cond.any_keywords.clone().unwrap_or_default();
    let all = cond.all_keywords.clone().unwrap_or_default();

    if !all.is_empty() {
        for k in all {
            let kk = if ci { k.to_lowercase() } else { k };
            if !t.contains(&kk) {
                return false;
            }
        }
    }
    if !any.is_empty() {
        let mut ok = false;
        for k in any {
            let kk = if ci { k.to_lowercase() } else { k };
            if t.contains(&kk) {
                ok = true;
                break;
            }
        }
        if !ok {
            return false;
        }
    }

    if !compiled.is_empty() {
        return compiled.iter().any(|r| r.is_match(text));
    }

    !(cond.any_keywords.as_ref().map(|v| v.is_empty()).unwrap_or(true)
        && cond.all_keywords.as_ref().map(|v| v.is_empty()).unwrap_or(true)
        && cond.regex.as_ref().map(|v| v.is_empty()).unwrap_or(true))
}

fn perms_from_cfg(p: &PermissionsCfg) -> ChatPermissions {
    let mut perms = ChatPermissions::empty();

    if p.can_send_messages {
        perms.insert(ChatPermissions::SEND_MESSAGES);
    }
    if p.can_send_media_messages {
        perms.insert(ChatPermissions::SEND_MEDIA_MESSAGES);
    }
    if p.can_send_polls {
        perms.insert(ChatPermissions::SEND_POLLS);
    }
    if p.can_send_other_messages {
        perms.insert(ChatPermissions::SEND_OTHER_MESSAGES);
    }
    if p.can_add_web_page_previews {
        perms.insert(ChatPermissions::ADD_WEB_PAGE_PREVIEWS);
    }
    if p.can_change_info {
        perms.insert(ChatPermissions::CHANGE_INFO);
    }
    if p.can_invite_users {
        perms.insert(ChatPermissions::INVITE_USERS);
    }
    if p.can_pin_messages {
        perms.insert(ChatPermissions::PIN_MESSAGES);
    }

    perms
}

fn full_permissions() -> ChatPermissions {
    ChatPermissions::all()
}

fn ctx_perm_hint(ctx: &str) -> &'static str {
    match ctx {
        "restrict_chat_member" => "需要管理员权限（限制成员发言），并且群内必须授予 bot Restrict/Ban 权限",
        "kick_chat_member" => "需要管理员权限（踢人），并且群内必须授予 bot Ban users 权限",
        "ban_chat_member" => "需要管理员权限（封禁），并且群内必须授予 bot Ban users 权限",
        "delete_message" => "需要管理员权限（删消息），并且群内必须授予 bot Delete messages 权限",
        "get_chat_administrators" => "需要 bot 能读取管理员列表（通常无需额外权限，但被限制时会失败）",
        "send_message" => "需要 bot 能在对应会话发消息；私聊时用户可能未 /start 或已屏蔽 bot",
        "edit_message_text" => "需要 bot 能编辑自己发的消息（仅能编辑 bot 自己发送的消息）",
        "answer_callback_query" => "用于按钮回调确认；一般不会失败，失败多为网络/请求异常",
        _ => "检查 bot 是否为群管理员、以及是否授予了对应权限",
    }
}

async fn api_log<R>(ctx: &str, req: R) -> Option<<R::Payload as Payload>::Output>
where
    R: Request + HasPayload,
{
    match req.send().await {
        Ok(v) => Some(v),
        Err(e) => {
            warn!(
                "API call failed ({ctx}): {:?}; hint: {}",
                e,
                ctx_perm_hint(ctx)
            );
            None
        }
    }
}

fn group_snapshot_path(data_dir: &str, chat_id: i64) -> PathBuf {
    PathBuf::from(format!(
        "{}/{}{}{}",
        data_dir, GROUP_SNAPSHOT_PREFIX, chat_id, GROUP_SNAPSHOT_SUFFIX
    ))
}

fn write_atomic(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = PathBuf::from(format!("{}{}", path.display(), TEMP_FILE_SUFFIX));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn persist_group(gs: &GroupState, data_dir: &str) -> Result<()> {
    let now = Utc::now();
    let path = group_snapshot_path(data_dir, gs.cfg.chat_id);

    let mut verify = Vec::new();
    for entry in gs.verify.iter() {
        let ((chat_id, uid), sess) = entry.pair();
        if now <= sess.expires_at {
            verify.push(PersistVerify {
                chat_id: chat_id.0,
                user_id: uid.0,
                question_id: sess.question_id.clone(),
                shuffled_options: sess.shuffled_options.clone(),
                correct_index: sess.correct_index,
                attempts_left: sess.attempts_left,
                expires_at: sess.expires_at,
            });
        }
    }

    let mut warns = Vec::new();
    for entry in gs.warns.iter() {
        let ((chat_id, uid, rule_name), ts) = entry.pair();
        warns.push(PersistWarn {
            chat_id: chat_id.0,
            user_id: uid.0,
            rule_name: rule_name.clone(),
            timestamps: ts.clone(),
        });
    }

    let snap = PersistSnapshot {
        verify,
        warns,
        saved_at: now,
    };

    let bytes = serde_json::to_vec_pretty(&snap)?;
    write_atomic(&path, &bytes)?;
    Ok(())
}

async fn persist_group_async(gs: &GroupState, data_dir: &str) {
    let now = Utc::now();
    let path = group_snapshot_path(data_dir, gs.cfg.chat_id);

    let mut verify = Vec::new();
    for entry in gs.verify.iter() {
        let ((chat_id, uid), sess) = entry.pair();
        if now <= sess.expires_at {
            verify.push(PersistVerify {
                chat_id: chat_id.0,
                user_id: uid.0,
                question_id: sess.question_id.clone(),
                shuffled_options: sess.shuffled_options.clone(),
                correct_index: sess.correct_index,
                attempts_left: sess.attempts_left,
                expires_at: sess.expires_at,
            });
        }
    }

    let mut warns = Vec::new();
    for entry in gs.warns.iter() {
        let ((chat_id, uid, rule_name), ts) = entry.pair();
        warns.push(PersistWarn {
            chat_id: chat_id.0,
            user_id: uid.0,
            rule_name: rule_name.clone(),
            timestamps: ts.clone(),
        });
    }

    let snap = PersistSnapshot {
        verify,
        warns,
        saved_at: now,
    };

    let bytes = match serde_json::to_vec_pretty(&snap) {
        Ok(b) => b,
        Err(e) => {
            warn!("persist_group_async serialize failed: {:?}", e);
            return;
        }
    };

    let _ = tokio::task::spawn_blocking(move || write_atomic(&path, &bytes))
        .await
        .map_err(|e| {
            warn!("persist_group_async join error: {:?}", e);
        })
        .and_then(|r| {
            if let Err(e) = r {
                warn!("persist_group_async write failed: {:?}", e);
            }
            Ok(())
        });
}

fn restore_group(gs: &GroupState, data_dir: &str) -> Result<()> {
    let now = Utc::now();
    let path = group_snapshot_path(data_dir, gs.cfg.chat_id);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };
    let snap: PersistSnapshot = serde_json::from_str(&text)?;

    for v in snap.verify {
        if now <= v.expires_at {
            gs.verify.insert(
                (ChatId(v.chat_id), UserId(v.user_id)),
                VerifySession {
                    question_id: v.question_id,
                    shuffled_options: v.shuffled_options,
                    correct_index: v.correct_index,
                    attempts_left: v.attempts_left,
                    expires_at: v.expires_at,
                },
            );
        }
    }

    for w in snap.warns {
        gs.warns.insert(
            (ChatId(w.chat_id), UserId(w.user_id), w.rule_name),
            w.timestamps,
        );
    }
    Ok(())
}

fn parse_hhmm_utc(s: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let hh = parts[0].parse::<u32>().ok()?;
    let mm = parts[1].parse::<u32>().ok()?;
    if hh > 23 || mm > 59 {
        return None;
    }
    Some((hh, mm))
}

fn next_daily_in_utc(hh: u32, mm: u32) -> DateTime<Utc> {
    let now = Utc::now();
    let today = now.date_naive();
    let candidate = today
        .and_hms_opt(hh, mm, 0)
        .unwrap_or_else(|| today.and_hms_opt(0, 0, 0).unwrap());
    let cand_dt = DateTime::<Utc>::from_naive_utc_and_offset(candidate, Utc);
    if cand_dt > now {
        cand_dt
    } else {
        let tomorrow = today.succ_opt().unwrap_or(today);
        let t = tomorrow
            .and_hms_opt(hh, mm, 0)
            .unwrap_or_else(|| tomorrow.and_hms_opt(0, 0, 0).unwrap());
        DateTime::<Utc>::from_naive_utc_and_offset(t, Utc)
    }
}

fn file_mtime_utc(p: &Path) -> Option<DateTime<Utc>> {
    let meta = std::fs::metadata(p).ok()?;
    let mt: SystemTime = meta.modified().ok()?;
    Some(DateTime::<Utc>::from(mt))
}

fn list_snapshot_files(data_dir: &str, prefix: &str, suffix: &str) -> Vec<PathBuf> {
    let mut out = vec![];
    let rd = match std::fs::read_dir(data_dir) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if !p.is_file() {
            continue;
        }
        let name = match p.file_name().and_then(|x| x.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name.starts_with(prefix) && name.ends_with(suffix) {
            out.push(p);
        }
    }
    out
}

fn disk_free_percent(path: &str) -> Option<u8> {
    let out = Command::new("df").args(["-P", path]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let mut lines = s.lines();
    let _hdr = lines.next()?;
    let line = lines.next()?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 5 {
        return None;
    }
    let cap = cols[4].trim();
    let used_pct = cap.trim_end_matches('%').parse::<u8>().ok()?;
    Some(100u8.saturating_sub(used_pct))
}

fn cleanup_snapshots_once(data_dir: &str, cfg: &SnapshotCleanupCfg) {
    let prefix = cfg
        .filename_prefix
        .as_deref()
        .unwrap_or(GROUP_SNAPSHOT_PREFIX);
    let suffix = cfg
        .filename_suffix
        .as_deref()
        .unwrap_or(GROUP_SNAPSHOT_SUFFIX);

    let mut files = list_snapshot_files(data_dir, prefix, suffix);
    if files.is_empty() {
        return;
    }

    let now = Utc::now();

    if let Some(days) = cfg.retention_days {
        if days > 0 {
            let keep = chrono::Duration::days(days);
            for p in &files {
                if let Some(mt) = file_mtime_utc(p) {
                    if now - mt > keep {
                        if let Err(e) = std::fs::remove_file(p) {
                            warn!(
                                "snapshot cleanup (retention) remove failed: {}: {:?}",
                                p.display(),
                                e
                            );
                        }
                    }
                }
            }
            files = list_snapshot_files(data_dir, prefix, suffix);
        }
    }

    let enable_disk_guard = cfg.enable_disk_guard.unwrap_or(true);
    if enable_disk_guard {
        let low = cfg.disk_free_percent_low.unwrap_or(10);
        if let Some(free) = disk_free_percent(data_dir) {
            if free < low {
                let frac = cfg.delete_oldest_fraction.unwrap_or(0.35);
                let mut dated: Vec<(DateTime<Utc>, PathBuf)> = files
                    .into_iter()
                    .filter_map(|p| file_mtime_utc(&p).map(|mt| (mt, p)))
                    .collect();
                dated.sort_by_key(|(mt, _)| *mt);
                let n = dated.len();
                if n > 0 {
                    let mut del = ((n as f64) * frac).ceil() as usize;
                    if del == 0 {
                        del = 1;
                    }
                    del = del.min(n);
                    warn!(
                        "disk guard triggered (free={}%), deleting oldest {}/{} snapshot files (fraction={})",
                        free, del, n, frac
                    );
                    for (_mt, p) in dated.into_iter().take(del) {
                        if let Err(e) = std::fs::remove_file(&p) {
                            warn!(
                                "snapshot cleanup (disk_guard) remove failed: {}: {:?}",
                                p.display(),
                                e
                            );
                        }
                    }
                }
            }
        }
    }
}

async fn snapshot_cleanup_task(state: AppState, mut shutdown_rx: broadcast::Receiver<()>) {
    let Some(cfg) = state.runtime.snapshots.clone() else {
        return;
    };
    if cfg.enable_daily_cleanup.unwrap_or(true) == false {
        return;
    }

    let hhmm = cfg.daily_cleanup_at.clone().unwrap_or_else(|| "03:30".to_string());
    let (hh, mm) = parse_hhmm_utc(&hhmm).unwrap_or((3, 30));

    loop {
        let next = next_daily_in_utc(hh, mm);
        let now = Utc::now();
        let sleep = (next - now).to_std().unwrap_or(Duration::from_secs(3600));

        tokio::select! {
            _ = shutdown_rx.recv() => { break; }
            _ = tokio::time::sleep(sleep) => {
                cleanup_snapshots_once(&state.data_dir, &cfg);
            }
        }
    }
}

fn warning_window_minutes(gs: &GroupState, rule_name: &str) -> Option<i64> {
    gs.cfg
        .warnings
        .iter()
        .find(|r| r.name == rule_name)
        .map(|r| r.window_minutes)
}

fn prune_warns(gs: &GroupState) -> bool {
    let now = Utc::now();
    let mut changed = false;

    let keys: Vec<(ChatId, UserId, String)> = gs.warns.iter().map(|e| e.key().clone()).collect();

    for (chat_id, uid, rule_name) in keys {
        let Some(window_min) = warning_window_minutes(gs, &rule_name) else {
            gs.warns.remove(&(chat_id, uid, rule_name));
            changed = true;
            continue;
        };
        let window = chrono::Duration::minutes(window_min);
        if let Some(mut v) = gs.warns.get_mut(&(chat_id, uid, rule_name.clone())) {
            v.retain(|ts| now - *ts <= window);
            if v.is_empty() {
                drop(v);
                gs.warns.remove(&(chat_id, uid, rule_name));
                changed = true;
            }
        }
    }

    changed
}

async fn prune_verify_and_apply_fail(bot: &Bot, gs: &GroupState, data_dir: &str) {
    let now = Utc::now();
    let keys: Vec<(ChatId, UserId)> = gs.verify.iter().map(|e| e.key().clone()).collect();

    let mut changed = false;
    for (gid, uid) in keys {
        if let Some(sess) = gs.verify.get(&(gid, uid)) {
            if now > sess.expires_at {
                gs.verify.remove(&(gid, uid));
                changed = true;
                let _ = apply_fail(bot, gs, gid, uid, "验证超时").await;
            }
        }
    }

    if changed || prune_warns(gs) {
        persist_group_async(gs, data_dir).await;
    }
}

fn clear_warn_record(gs: &GroupState, chat_id: ChatId, uid: UserId, rule_name: &str) {
    gs.warns.remove(&(chat_id, uid, rule_name.to_string()));
}

async fn refresh_admins(bot: &Bot, gs: &GroupState) -> Result<()> {
    let chat_id = ChatId(gs.cfg.chat_id);
    let admins = bot
        .get_chat_administrators(chat_id)
        .send()
        .await
        .with_context(|| "get_chat_administrators")?;
    gs.admins.clear();
    for m in admins {
        gs.admins.insert(m.user.id, true);
    }
    Ok(())
}

async fn is_admin(gs: &GroupState, uid: UserId) -> bool {
    gs.admins.get(&uid).is_some()
}

fn format_template(s: &str, vars: &HashMap<&str, String>) -> String {
    let mut out = s.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{}}}", k), v);
    }
    out
}

async fn enqueue_group_notice(state: &AppState, group_id: ChatId, user: (UserId, String)) {
    if state.runtime.merge_group_notice.unwrap_or(true) == false {
        return;
    }
    let mut guard = state.merged_notice.lock().await;
    let buf = guard.entry(group_id).or_insert_with(|| MergedNoticeBuffer {
        users: vec![],
        last_sent: Utc::now(),
    });
    buf.users.push(user);
}

async fn flush_group_notice(bot: &Bot, state: &AppState) -> Result<()> {
    let interval = state.runtime.merge_group_notice_interval_secs.unwrap_or(8);
    let max_names = state.runtime.merge_group_notice_max_names.unwrap_or(6);

    let mut guard = state.merged_notice.lock().await;
    let now = Utc::now();

    for (gid, buf) in guard.iter_mut() {
        let elapsed = (now - buf.last_sent).num_seconds();
        if buf.users.is_empty() || elapsed < interval as i64 {
            continue;
        }

        let mut names: Vec<String> = buf.users.iter().map(|(_, n)| n.clone()).collect();
        names.sort();
        names.dedup();

        let shown: Vec<String> = names.iter().take(max_names).cloned().collect();
        let more = names.len().saturating_sub(shown.len());

        let names_text = if more > 0 {
            format!("{} 等 {} 人", shown.join("、"), names.len())
        } else {
            shown.join("、")
        };

        let slowest = buf.users.last().map(|(_, n)| n.clone()).unwrap_or_default();

        if let Some(gs) = state.groups.get(gid) {
            // ✅ 没有 join_verification 就不发入群验证提示
            let Some(jv) = gs.cfg.join_verification.as_ref() else {
                buf.users.clear();
                buf.last_sent = now;
                continue;
            };
            if !jv.enabled {
                buf.users.clear();
                buf.last_sent = now;
                continue;
            }

            let mut vars = HashMap::new();
            vars.insert("names", names_text);
            vars.insert("bot_username", format!("@{}", state.bot_username));
            vars.insert("group_name", gs.cfg.name.clone());
            vars.insert("slowest", slowest);

            let text = format_template(&jv.group_notice_template, &vars);
            let _ = api_log("send_message", bot.send_message(*gid, text)).await;
        }

        buf.users.clear();
        buf.last_sent = now;
    }
    Ok(())
}

fn cb_data(gid: ChatId, idx: usize) -> String {
    format!("{}:{}:{}", CALLBACK_PREFIX, gid.0, idx)
}

fn parse_callback_data(data: &str) -> Option<(ChatId, usize)> {
    let parts: Vec<&str> = data.split(':').collect();
    if parts.len() != 3 || parts[0] != CALLBACK_PREFIX {
        return None;
    }
    let gid_i64 = parts[1].parse::<i64>().ok()?;
    let idx = parts[2].parse::<usize>().ok()?;
    Some((ChatId(gid_i64), idx))
}

fn build_keyboard(gid: ChatId, options: &[String]) -> InlineKeyboardMarkup {
    let rows: Vec<Vec<InlineKeyboardButton>> = options
        .iter()
        .enumerate()
        .map(|(i, text)| vec![InlineKeyboardButton::callback(text.clone(), cb_data(gid, i))])
        .collect();
    InlineKeyboardMarkup::new(rows)
}

fn pick_and_shuffle_question(gs: &GroupState) -> Result<(Question, Vec<String>, usize)> {
    let jv = gs
        .cfg
        .join_verification
        .as_ref()
        .context("join_verification is missing")?;

    let q = jv
        .questions
        .choose(&mut rand::thread_rng())
        .context("questions empty")?
        .clone();

    let correct_pos_in_original = q
        .options
        .iter()
        .position(|x| x == &q.answer)
        .with_context(|| format!("question {} answer not found in options", q.id))?;

    let correct_text = q.options[correct_pos_in_original].clone();

    let mut shuffled = q.options.clone();
    shuffled.shuffle(&mut rand::thread_rng());

    let correct_index = shuffled
        .iter()
        .position(|x| x == &correct_text)
        .context("correct index not found after shuffle")?;

    Ok((q, shuffled, correct_index))
}

async fn send_or_edit_question_dm(
    bot: &Bot,
    uid: UserId,
    gid: ChatId,
    gs: &GroupState,
    q: &Question,
    shuffled: &[String],
    attempts_left: u32,
    edit_target: Option<(ChatId, MessageId)>,
) {
    let Some(jv) = gs.cfg.join_verification.as_ref() else {
        return;
    };

    let mut vars = HashMap::new();
    vars.insert("group_name", gs.cfg.name.clone());
    vars.insert("timeout_secs", jv.timeout_secs.to_string());
    let intro = format_template(&jv.dm_intro, &vars);

    let mut text = format!("{}\n\n{}", intro, q.prompt);

    if jv.max_attempts > 0 {
        text.push_str(&format!("\n\n剩余重试次数：{}", attempts_left));
    }

    let kb = build_keyboard(gid, shuffled);

    match edit_target {
        Some((chat_id, mid)) => {
            let _ = api_log(
                "edit_message_text",
                bot.edit_message_text(chat_id, mid, text).reply_markup(kb),
            )
            .await;
        }
        None => {
            let ok = api_log(
                "send_message",
                bot.send_message(ChatId(uid.0 as i64), text).reply_markup(kb),
            )
            .await
            .is_some();

            if !ok {
                let _ = api_log(
                    "send_message",
                    bot.send_message(
                        gid,
                        format!(
                            "⚠️ 无法私聊发送验证题给用户 {:?}（可能未私聊 bot /start 或屏蔽 bot）。请管理员提醒其先私聊 bot 再验证。",
                            uid
                        ),
                    ),
                )
                .await;
            }
        }
    }
}

async fn handle_new_members(bot: &Bot, state: &AppState, msg: &Message) -> Result<()> {
    let chat_id = msg.chat.id;
    let Some(gs) = state.groups.get(&chat_id) else { return Ok(()); };

    // ✅ 没有 join_verification / 或 enabled=false 就完全不做加群验证
    let Some(jv) = gs.cfg.join_verification.as_ref() else { return Ok(()); };
    if !jv.enabled {
        return Ok(());
    }

    if gs.admins.is_empty() {
        let _ = refresh_admins(bot, gs).await;
    }

    let new_members = msg.new_chat_members().unwrap_or(&[]);
    for u in new_members {
        if gs.cfg.ignore_admins.unwrap_or(true) && is_admin(gs, u.id).await {
            continue;
        }

        let perms = perms_from_cfg(&jv.restrict);
        let _ = api_log(
            "restrict_chat_member",
            bot.restrict_chat_member(chat_id, u.id, perms),
        )
        .await;

        let (q, shuffled, correct_index) = pick_and_shuffle_question(gs)?;

        let expires_at = Utc::now() + chrono::Duration::seconds(jv.timeout_secs as i64);

        gs.verify.insert(
            (chat_id, u.id),
            VerifySession {
                question_id: q.id.clone(),
                shuffled_options: shuffled.clone(),
                correct_index,
                attempts_left: jv.max_attempts,
                expires_at,
            },
        );

        persist_group_async(gs, &state.data_dir).await;

        enqueue_group_notice(state, chat_id, (u.id, u.full_name())).await;

        send_or_edit_question_dm(
            bot,
            u.id,
            chat_id,
            gs,
            &q,
            &shuffled,
            jv.max_attempts,
            None,
        )
        .await;
    }
    Ok(())
}

async fn handle_private_answer(bot: &Bot, state: &AppState, msg: &Message) -> Result<()> {
    if !msg.chat.is_private() {
        return Ok(());
    }
    let uid = msg.from.as_ref().map(|u| u.id).context("no from")?;
    let text = msg.text().unwrap_or("").trim();
    if text.is_empty() {
        return Ok(());
    }

    for (gid, gs) in &state.groups {
        let key = (*gid, uid);
        if gs.verify.get(&key).is_some() {
            let ok = api_log(
                "send_message",
                bot.send_message(msg.chat.id, "请直接点击题目下方按钮作答（无需输入 A/B/C/D）。"),
            )
            .await
            .is_some();

            if !ok {
                let _ = api_log(
                    "send_message",
                    bot.send_message(
                        *gid,
                        format!(
                            "⚠️ 用户 {:?} 私聊提示发送失败（可能未 /start 或屏蔽 bot）。请管理员提醒其先私聊 bot /start 后再验证。",
                            uid
                        ),
                    ),
                )
                .await;
            }

            return Ok(());
        }
    }

    Ok(())
}

async fn process_callback_correct(
    bot: &Bot,
    gs: &GroupState,
    gid: ChatId,
    uid: UserId,
    q: CallbackQuery,
    data_dir: &str,
) -> Result<()> {
    let _ = api_log(
        "restrict_chat_member",
        bot.restrict_chat_member(gid, uid, full_permissions()),
    )
    .await;

    if let Some(jv) = gs.cfg.join_verification.as_ref() {
        if let Some(w) = &jv.on_pass.welcome_dm {
            let _ = api_log("send_message", bot.send_message(ChatId(uid.0 as i64), w.clone())).await;
        } else {
            let _ = api_log(
                "send_message",
                bot.send_message(ChatId(uid.0 as i64), "验证通过，已解除限制。"),
            )
            .await;
        }
    }

    persist_group_async(gs, data_dir).await;

    let _ = api_log(
        "answer_callback_query",
        bot.answer_callback_query(q.id).text("验证通过。"),
    )
    .await;

    if let Some(msg) = q.message {
        let _ = api_log(
            "edit_message_text",
            bot.edit_message_text(msg.chat().id, msg.id(), "✅ 验证通过")
                .reply_markup(InlineKeyboardMarkup::new(
                    Vec::<Vec<InlineKeyboardButton>>::new(),
                )),
        )
        .await;
    }

    Ok(())
}

async fn process_callback_wrong(
    bot: &Bot,
    gs: &GroupState,
    gid: ChatId,
    uid: UserId,
    mut sess: VerifySession,
    q: CallbackQuery,
    qcfg: Question,
    data_dir: &str,
) -> Result<()> {
    let max_attempts = gs
        .cfg
        .join_verification
        .as_ref()
        .map(|jv| jv.max_attempts)
        .unwrap_or(0);

    if max_attempts == 0 || sess.attempts_left == 0 {
        let _ = apply_fail(bot, gs, gid, uid, "回答错误").await;

        persist_group_async(gs, data_dir).await;

        let _ = api_log(
            "answer_callback_query",
            bot.answer_callback_query(q.id).text("回答错误，验证失败。"),
        )
        .await;

        if let Some(msg) = q.message {
            let _ = api_log(
                "edit_message_text",
                bot.edit_message_text(msg.chat().id, msg.id(), "❌ 回答错误，验证失败")
                    .reply_markup(InlineKeyboardMarkup::new(
                        Vec::<Vec<InlineKeyboardButton>>::new(),
                    )),
            )
            .await;
        }
        return Ok(());
    }

    if sess.attempts_left > 0 {
        sess.attempts_left -= 1;
    }
    let attempts_left_now = sess.attempts_left;

    let correct_text = qcfg.answer.clone();
    let mut shuffled = qcfg.options.clone();
    shuffled.shuffle(&mut rand::thread_rng());

    let correct_index = shuffled
        .iter()
        .position(|x| x == &correct_text)
        .context("correct index not found after reshuffle")?;

    sess.shuffled_options = shuffled.clone();
    sess.correct_index = correct_index;

    gs.verify.insert((gid, uid), sess);

    persist_group_async(gs, data_dir).await;

    let _ = api_log(
        "answer_callback_query",
        bot.answer_callback_query(q.id).text("回答不正确，请重试。"),
    )
    .await;

    if let Some(msg) = q.message {
        send_or_edit_question_dm(
            bot,
            uid,
            gid,
            gs,
            &qcfg,
            &shuffled,
            attempts_left_now,
            Some((msg.chat().id, msg.id())),
        )
        .await;
    } else {
        send_or_edit_question_dm(bot, uid, gid, gs, &qcfg, &shuffled, attempts_left_now, None)
            .await;
    }

    Ok(())
}

async fn handle_callback_query(bot: &Bot, state: &AppState, q: CallbackQuery) -> Result<()> {
    let Some(data) = q.data.clone() else {
        return Ok(());
    };

    let Some((gid, idx)) = parse_callback_data(&data) else {
        return Ok(());
    };

    let uid = q.from.id;

    let Some(gs) = state.groups.get(&gid) else {
        let _ = api_log("answer_callback_query", bot.answer_callback_query(q.id)).await;
        return Ok(());
    };

    // ✅ 没有 join_verification 就不处理回调
    let Some(jv) = gs.cfg.join_verification.as_ref() else {
        let _ = api_log(
            "answer_callback_query",
            bot.answer_callback_query(q.id).text("本群未启用入群验证。"),
        )
        .await;
        return Ok(());
    };
    if !jv.enabled {
        let _ = api_log(
            "answer_callback_query",
            bot.answer_callback_query(q.id).text("本群未启用入群验证。"),
        )
        .await;
        return Ok(());
    }

    let key = (gid, uid);

    let Some((_k, sess)) = gs.verify.remove(&key) else {
        let _ = api_log(
            "answer_callback_query",
            bot.answer_callback_query(q.id).text("该验证已结束或不存在。"),
        )
        .await;
        return Ok(());
    };

    if Utc::now() > sess.expires_at {
        let _ = apply_fail(bot, gs, gid, uid, "验证超时").await;

        persist_group_async(gs, &state.data_dir).await;

        let _ = api_log(
            "answer_callback_query",
            bot.answer_callback_query(q.id).text("已超时，验证失败。"),
        )
        .await;
        return Ok(());
    }

    if idx >= sess.shuffled_options.len() {
        gs.verify.insert(key, sess);
        let _ = api_log(
            "answer_callback_query",
            bot.answer_callback_query(q.id).text("选项无效，请重新作答。"),
        )
        .await;
        return Ok(());
    }

    let qcfg = jv
        .questions
        .iter()
        .find(|qq| qq.id == sess.question_id)
        .cloned();

    let Some(qcfg) = qcfg else {
        let _ = apply_fail(bot, gs, gid, uid, "题库配置错误").await;

        persist_group_async(gs, &state.data_dir).await;

        let _ = api_log(
            "answer_callback_query",
            bot.answer_callback_query(q.id).text("题库错误，验证失败。"),
        )
        .await;
        return Ok(());
    };

    let correct = idx == sess.correct_index;

    if correct {
        process_callback_correct(bot, gs, gid, uid, q, &state.data_dir).await?;
        return Ok(());
    }

    process_callback_wrong(bot, gs, gid, uid, sess, q, qcfg, &state.data_dir).await?;
    Ok(())
}

async fn apply_fail(bot: &Bot, gs: &GroupState, gid: ChatId, uid: UserId, why: &str) -> Result<()> {
    let Some(jv) = gs.cfg.join_verification.as_ref() else {
        // 没有验证配置：理论上不会走到这里，直接静默
        return Ok(());
    };

    let reason = jv
        .on_fail
        .reason
        .clone()
        .unwrap_or_else(|| why.to_string());

    match jv.on_fail.action {
        PunishmentAction::Kick => {
            let _ = api_log("kick_chat_member", bot.kick_chat_member(gid, uid)).await;
        }
        PunishmentAction::Ban => {
            let minutes = jv.on_fail.ban_minutes.unwrap_or(0);
            if minutes <= 0 {
                let _ = api_log("ban_chat_member", bot.ban_chat_member(gid, uid)).await;
            } else {
                let until = Utc::now() + chrono::Duration::minutes(minutes);
                let _ = api_log(
                    "ban_chat_member",
                    bot.ban_chat_member(gid, uid).until_date(until),
                )
                .await;
            }
        }
    }

    let _ = api_log(
        "send_message",
        bot.send_message(gid, format!("用户 {:?} 处理：{}（{}）", uid, reason, why))
            .parse_mode(ParseMode::Html),
    )
    .await;
    Ok(())
}

fn parse_ban_command(text: &str) -> Option<UserId> {
    let t = text.trim();
    let parts: Vec<&str> = t.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let uid_str = parts[1].trim();
    if let Ok(n) = uid_str.parse::<u64>() {
        return Some(UserId(n));
    }
    None
}

async fn handle_group_message(bot: &Bot, state: &AppState, msg: &Message) -> Result<()> {
    if msg.chat.is_private() {
        return Ok(());
    }
    let chat_id = msg.chat.id;
    let Some(gs) = state.groups.get(&chat_id) else { return Ok(()); };

    if gs.cfg.ignore_admins.unwrap_or(true) {
        if let Some(from) = msg.from.as_ref() {
            if gs.admins.is_empty() {
                let _ = refresh_admins(bot, gs).await;
            }
            if is_admin(gs, from.id).await {
                return Ok(());
            }
        }
    }

    // ✅ commands 可选：不写就不处理任何群命令
    if let Some(cmd) = gs.cfg.commands.as_ref() {
        if cmd.enabled.unwrap_or(true) {
            if let Some(text) = msg.text() {
                let prefix = cmd.prefix.clone().unwrap_or("/".into());
                if text.starts_with(prefix.as_str()) {
                    if cmd.admin_only.unwrap_or(true) {
                        if let Some(from) = msg.from.as_ref() {
                            if gs.admins.is_empty() {
                                let _ = refresh_admins(bot, gs).await;
                            }
                            if !is_admin(gs, from.id).await {
                                return Ok(());
                            }
                        }
                    }

                    if text.starts_with("/ban") {
                        if let Some(uid) = parse_ban_command(text) {
                            let _ = apply_limit_action(
                                bot,
                                chat_id,
                                uid,
                                PunishmentAction::Kick,
                                None,
                                "manual /ban",
                            )
                            .await;
                        }
                        return Ok(());
                    }

                    return Ok(());
                }
            }
        }
    }

    let text = msg.text().unwrap_or("");
    if text.is_empty() {
        return Ok(());
    }
    let from = match msg.from.as_ref() {
        Some(u) => u,
        None => return Ok(()),
    };
    let uid = from.id;

    for rule in &gs.cfg.kicks {
        let compiled = compiled_regex(gs, &rule.name, &rule.cond)?;
        if match_text(&rule.cond, text, &compiled) {
            if rule.delete_message.unwrap_or(false) {
                let _ = api_log("delete_message", bot.delete_message(chat_id, msg.id)).await;
            }
            let reason = rule.reason.clone().unwrap_or_else(|| "rule kick".into());
            let _ = apply_limit_action(
                bot,
                chat_id,
                uid,
                rule.action.clone(),
                rule.ban_minutes,
                &reason,
            )
            .await;
            return Ok(());
        }
    }

    for rule in &gs.cfg.warnings {
        let compiled = compiled_regex(gs, &rule.name, &rule.cond)?;
        if match_text(&rule.cond, text, &compiled) {
            let key = (chat_id, uid, rule.name.clone());
            let now = Utc::now();
            let mut v = gs.warns.get(&key).map(|x| x.clone()).unwrap_or_default();
            let window = chrono::Duration::minutes(rule.window_minutes);
            v.retain(|ts| now - *ts <= window);
            v.push(now);
            let count = v.len() as u32;
            gs.warns.insert(key.clone(), v);

            let warn_text = rule
                .warn_message
                .replace("{count}", &count.to_string())
                .replace("{limit}", &rule.limit.to_string());
            let _ = api_log("send_message", bot.send_message(chat_id, warn_text)).await;

            persist_group_async(gs, &state.data_dir).await;

            if count >= rule.limit {
                let reason = rule
                    .on_limit
                    .reason
                    .clone()
                    .unwrap_or_else(|| "warning limit".into());
                let _ = apply_limit_action(
                    bot,
                    chat_id,
                    uid,
                    rule.on_limit.action.clone(),
                    rule.on_limit.ban_minutes,
                    &reason,
                )
                .await;

                clear_warn_record(gs, chat_id, uid, &rule.name);

                persist_group_async(gs, &state.data_dir).await;
            }
        }
    }

    for rule in &gs.cfg.auto_replies {
        let compiled = compiled_regex(gs, &rule.name, &rule.cond)?;
        if match_text(&rule.cond, text, &compiled) {
            let _ = api_log("send_message", bot.send_message(chat_id, rule.reply.clone())).await;
        }
    }

    Ok(())
}

fn compiled_regex(gs: &GroupState, rule_name: &str, cond: &MatchCond) -> Result<Vec<Regex>> {
    if let Some(v) = gs.rule_regex.get(rule_name) {
        return Ok(v.clone());
    }
    let mut out = vec![];
    if let Some(list) = &cond.regex {
        for pat in list {
            out.push(Regex::new(pat).with_context(|| format!("bad regex in rule {}", rule_name))?);
        }
    }
    gs.rule_regex.insert(rule_name.to_string(), out.clone());
    Ok(out)
}

async fn apply_limit_action(
    bot: &Bot,
    chat_id: ChatId,
    uid: UserId,
    action: PunishmentAction,
    ban_minutes: Option<i64>,
    reason: &str,
) -> Result<()> {
    match action {
        PunishmentAction::Kick => {
            let _ = api_log("kick_chat_member", bot.kick_chat_member(chat_id, uid)).await;
        }
        PunishmentAction::Ban => {
            let m = ban_minutes.unwrap_or(0);
            if m <= 0 {
                let _ = api_log("ban_chat_member", bot.ban_chat_member(chat_id, uid)).await;
            } else {
                let until = Utc::now() + chrono::Duration::minutes(m);
                let _ = api_log(
                    "ban_chat_member",
                    bot.ban_chat_member(chat_id, uid).until_date(until),
                )
                .await;
            }
        }
    }
    let _ = api_log(
        "send_message",
        bot.send_message(chat_id, format!("处理用户 {:?}：{}", uid, reason)),
    )
    .await;
    Ok(())
}

async fn network_time_probe() {
    let now = Utc::now();
    info!("time_probe: local_utc_now={}", now.to_rfc3339());
}

fn schema() -> UpdateHandler<anyhow::Error> {
    dptree::entry()
        .branch(
            Update::filter_message().endpoint(
                |bot: Bot, state: Arc<AppState>, msg: Message| async move {
                    if msg.new_chat_members().is_some() {
                        let _ = handle_new_members(&bot, &state, &msg).await;
                    }
                    if msg.chat.is_private() {
                        let _ = handle_private_answer(&bot, &state, &msg).await;
                    } else {
                        let _ = handle_group_message(&bot, &state, &msg).await;
                    }
                    Ok(())
                },
            ),
        )
        .branch(
            Update::filter_callback_query().endpoint(
                |bot: Bot, state: Arc<AppState>, q: CallbackQuery| async move {
                    let _ = handle_callback_query(&bot, &state, q).await;
                    Ok(())
                },
            ),
        )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args_all: Vec<String> = std::env::args().collect();
    let autostart = parse_autostart_arg(&args_all);

    match autostart {
        AutoStartOpt::On => {
            enable_autostart(&args_all)?;
        }
        AutoStartOpt::Off | AutoStartOpt::Unspecified => {
            let _ = disable_autostart();
        }
    }

    let config_path = std::env::args().skip(1).collect::<Vec<_>>();
    let config_path =
        parse_config_arg(&config_path).unwrap_or_else(|| PathBuf::from("config.yaml"));

    let cfg = load_config(&config_path)?;
    validate_config(&cfg)?;

    let filter = cfg.bot.log_level.clone().unwrap_or_else(|| "info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let (shutdown_tx, _shutdown_rx0) = broadcast::channel::<()>(8);

    let shutdown_ctrl = shutdown_tx.clone();
    let ctrl_handle = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_ctrl.send(());
    });

    let bot = Bot::new(cfg.bot.token.clone());

    let me = bot.get_me().send().await?;
    let bot_username = me.user.username.clone().unwrap_or_else(|| "bot".into());

    let data_dir = cfg
        .runtime
        .data_dir
        .clone()
        .unwrap_or_else(|| "./data".to_string());

    let mut groups_map = HashMap::new();
    for g in &cfg.groups {
        let gs = GroupState {
            cfg: g.clone(),
            admins: DashMap::new(),
            verify: DashMap::new(),
            warns: DashMap::new(),
            rule_regex: DashMap::new(),
        };
        let gid = ChatId(g.chat_id);
        groups_map.insert(gid, Arc::new(gs));
    }

    let state = AppState {
        groups: groups_map,
        bot_username,
        merged_notice: Arc::new(Mutex::new(HashMap::new())),
        runtime: cfg.runtime.clone(),
        data_dir: data_dir.clone(),
    };

    for (gid, gs) in &state.groups {
        if let Err(e) = refresh_admins(&bot, gs).await {
            warn!("refresh_admins failed (startup): {:?}", e);
        }
        if let Err(e) = restore_group(gs, &state.data_dir) {
            warn!("restore_group failed (startup): {:?}", e);
        }
        if let Err(e) = persist_group(gs, &state.data_dir) {
            warn!("persist_group failed (startup): {:?}", e);
        }
        info!("Loaded group {} ({:?})", gs.cfg.name, gid);
    }

    let bot_admin = bot.clone();
    let state_admin = state.clone();
    let mut shutdown_rx_admin = shutdown_tx.subscribe();
    let h_admin = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(180));
        loop {
            tokio::select! {
                _ = shutdown_rx_admin.recv() => { break; }
                _ = ticker.tick() => {
                    for (_gid, gs) in &state_admin.groups {
                        if let Err(e) = refresh_admins(&bot_admin, gs).await {
                            warn!("refresh_admins failed: {:?}", e);
                        }
                    }
                }
            }
        }
    });

    let mut shutdown_rx_time = shutdown_tx.subscribe();
    let h_time = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(180));
        loop {
            tokio::select! {
                _ = shutdown_rx_time.recv() => { break; }
                _ = ticker.tick() => {
                    network_time_probe().await;
                }
            }
        }
    });

    let bot_gc = bot.clone();
    let state_gc = state.clone();
    let mut shutdown_rx_gc = shutdown_tx.subscribe();
    let h_gc = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = shutdown_rx_gc.recv() => { break; }
                _ = ticker.tick() => {
                    for (_gid, gs) in &state_gc.groups {
                        prune_verify_and_apply_fail(&bot_gc, gs, &state_gc.data_dir).await;
                    }
                }
            }
        }
    });

    let state_snap = state.clone();
    let shutdown_rx_snap = shutdown_tx.subscribe();
    let h_snap = tokio::spawn(async move {
        snapshot_cleanup_task(state_snap, shutdown_rx_snap).await;
    });

    let bot2 = bot.clone();
    let state2 = state.clone();
    let mut shutdown_rx_flush = shutdown_tx.subscribe();
    let h_flush = tokio::spawn(async move {
        let secs = state2.runtime.merge_group_notice_interval_secs.unwrap_or(8);
        let mut ticker = tokio::time::interval(Duration::from_secs(secs));
        loop {
            tokio::select! {
                _ = shutdown_rx_flush.recv() => { break; }
                _ = ticker.tick() => {
                    if state2.runtime.merge_group_notice.unwrap_or(true) {
                        let _ = flush_group_notice(&bot2, &state2).await;
                    }
                }
            }
        }
    });

    let timeout = cfg.bot.polling_timeout_secs.unwrap_or(25);
    info!("Start polling as @{}", state.bot_username);

    let shared_state = Arc::new(state);
    let _ = timeout;

    Dispatcher::builder(bot, schema())
        .dependencies(dptree::deps![shared_state])
        .default_handler(|upd| async move {
            let _ = upd;
        })
        .error_handler(LoggingErrorHandler::with_custom_text("Dispatcher error"))
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;

    let _ = shutdown_tx.send(());
    let _ = ctrl_handle.await;
    let _ = h_admin.await;
    let _ = h_time.await;
    let _ = h_gc.await;
    let _ = h_snap.await;
    let _ = h_flush.await;

    Ok(())
}

fn parse_config_arg(args: &[String]) -> Option<PathBuf> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            return Some(PathBuf::from(&args[i + 1]));
        }
        i += 1;
    }
    None
}
