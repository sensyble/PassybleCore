//! A Team's password mode on this PC.
//!
//! * Mode: each Team's `policy.password_mode` (the member's override, else the team's), kept in `settings.json`.
//!   With several Teams `second_password` wins, then `one_password`, else `choice`. A Family is always `choice`.
//! * A second password: a vault in the list whose file opens with its own password while signed in to a Team
//!   account. It is reported to the account service when it changes, which then refuses this account's shares too.
//! * `second_password` until the active vault (whose keyset opens the shared vaults) has its own password: the
//!   team's vaults are handed to the agent as not writable, and nothing can be shared from here.
//! * `one_password`: no vault offers "Use a separate password"; vaults with their own password get a notice
//!   whose button runs the link flow.
//! * Sharing in a Team only outside `second_password`, without a second password here and while the service's
//!   `sharing_blocked` is false.
//!
//! [`team_rule_vaults`] alone decides which vaults a Team's rule covers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use pass_agent::{Agent, LinkedVaultConfig, PasswordPolicy, PasswordPolicyMode};
use serde_json::{json, Value};
use tauri::AppHandle;

use crate::commands::app_state;
use crate::i18n::{tr, trn};
use crate::teams::CachedOrg;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Choice,
    SecondPassword,
    OnePassword,
}

impl Mode {
    /// The service's name; anything else (a missing key, an older service) is `choice`.
    pub fn parse(name: Option<&str>) -> Mode {
        match name {
            Some("second_password") => Mode::SecondPassword,
            Some("one_password") => Mode::OnePassword,
            _ => Mode::Choice,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Choice => "choice",
            Mode::SecondPassword => "second_password",
            Mode::OnePassword => "one_password",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Mode::Choice => 0,
            Mode::OnePassword => 1,
            Mode::SecondPassword => 2,
        }
    }
}

pub fn org_mode(org: &CachedOrg) -> Mode {
    if org.kind != "team" {
        return Mode::Choice;
    }
    let policy: Value = serde_json::from_str(&org.policy).unwrap_or_default();
    Mode::parse(policy.get("password_mode").and_then(Value::as_str))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedVault {
    pub id: String,
    pub name: String,
    /// Its file opens with a password of its own; `None` when the file can't be read here.
    pub own_password: Option<bool>,
    /// It holds the sharing keys; `None` when it isn't open.
    pub holds_keys: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TeamRuleScope {
    /// The vault that holds the Team's keys and carries the second password: `id`, name, and whether it still
    /// opens with the Passyble password.
    pub key_vault: Option<(String, String, bool)>,
    /// The vaults with a password of their own (`id`, name): the `one_password` notices and the share rule.
    pub counted: Vec<(String, String)>,
}

impl TeamRuleScope {
    fn is_key_vault(&self, vault_id: &str) -> bool {
        self.key_vault
            .as_ref()
            .is_some_and(|(id, _, _)| id == vault_id)
    }
}

/// The only place that decides which vaults a Team's password rule covers: the active (home) vault is the key
/// vault (its sharing keys open the Team's vaults), and every vault with its own password is counted.
pub fn team_rule_vaults(vaults: &[ListedVault], active: Option<&str>) -> TeamRuleScope {
    let key_vault = active
        .and_then(|id| vaults.iter().find(|v| v.id == id))
        .filter(|v| v.holds_keys != Some(false))
        .and_then(|v| Some((v.id.clone(), v.name.clone(), !v.own_password?)));
    let counted = vaults
        .iter()
        .filter(|v| v.own_password == Some(true))
        .map(|v| (v.id.clone(), v.name.clone()))
        .collect();
    TeamRuleScope { key_vault, counted }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rule {
    pub mode: Mode,
    teams: Vec<(String, bool)>,
    pub scope: TeamRuleScope,
}

impl Rule {
    pub fn new(orgs: &[CachedOrg], vaults: &[ListedVault], active: Option<&str>) -> Rule {
        let teams: Vec<(String, bool)> = orgs
            .iter()
            .filter(|o| o.kind == "team")
            .map(|o| (o.id.clone(), o.sharing_blocked))
            .collect();
        if teams.is_empty() {
            return Rule::default();
        }
        let mode = orgs
            .iter()
            .map(org_mode)
            .max_by_key(|m| m.rank())
            .unwrap_or_default();
        Rule {
            mode,
            teams,
            scope: team_rule_vaults(vaults, active),
        }
    }

    fn is_team(&self, org: &str) -> bool {
        self.teams.iter().any(|(id, _)| id == org)
    }

    pub fn second_password(&self) -> bool {
        !self.teams.is_empty() && !self.scope.counted.is_empty()
    }

    pub fn action_needed(&self) -> bool {
        match self.mode {
            Mode::Choice => false,
            Mode::SecondPassword => self
                .scope
                .key_vault
                .as_ref()
                .is_some_and(|(_, _, linked)| *linked),
            Mode::OnePassword => !self.scope.counted.is_empty(),
        }
    }

    pub fn team_read_only(&self) -> bool {
        self.mode == Mode::SecondPassword && self.action_needed()
    }

    pub fn read_only_refusal(&self, org: Option<&str>) -> Option<String> {
        (self.team_read_only() && org.is_some_and(|o| self.is_team(o)))
            .then(|| tr!("password_mode.read_only"))
    }

    /// Why this account can't share into organisation `org`, if so. Outside a Team: never.
    pub fn share_refusal(&self, org: &str) -> Option<String> {
        let blocked = self.teams.iter().find(|(id, _)| id == org)?.1;
        if self.mode == Mode::SecondPassword {
            Some(tr!("password_mode.sharing_off_required"))
        } else if blocked || self.second_password() {
            Some(tr!("password_mode.sharing_off"))
        } else {
            None
        }
    }

    /// Why vault `vault_id` can't get a separate password, if so. `holds_keys`: it holds the
    /// sharing keys, which keep the Passyble password except for the key vault of a
    /// Team that requires a second password.
    pub fn unlink_refusal(&self, vault_id: &str, holds_keys: bool) -> Option<String> {
        match self.mode {
            Mode::OnePassword => Some(tr!("password_mode.one_password_only")),
            Mode::SecondPassword if self.scope.is_key_vault(vault_id) => None,
            _ => holds_keys.then(|| tr!("account_keys.home_stays_linked")),
        }
    }

    /// Why vault `vault_id` can't move to the Passyble password, if so: the key vault while a
    /// second password is required.
    pub fn link_refusal(&self, vault_id: &str) -> Option<String> {
        (self.mode == Mode::SecondPassword && self.scope.is_key_vault(vault_id))
            .then(|| tr!("password_mode.keeps_second"))
    }

    fn home_name(&self) -> String {
        self.scope
            .key_vault
            .as_ref()
            .map(|(_, name, _)| name.clone())
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| tr!("onboarding.vault"))
    }

    pub fn texts(&self) -> Option<(String, String)> {
        match self.mode {
            Mode::Choice => None,
            Mode::SecondPassword => Some((
                tr!("password_mode.second_title"),
                if self.action_needed() {
                    tr!("password_mode.second_body", vault = self.home_name())
                } else {
                    tr!("password_mode.second_met", vault = self.home_name())
                },
            )),
            Mode::OnePassword => Some((
                tr!("password_mode.one_title"),
                match self.scope.counted.as_slice() {
                    [] => tr!("password_mode.one_met"),
                    [(_, name)] => tr!("password_mode.one_body", vault = name),
                    many => trn!("password_mode.one_body_many", many.len()),
                },
            )),
        }
    }

    /// `vaults.list` `password_policy` (docs/PROTOCOL.md).
    pub fn agent_policy(&self) -> Option<PasswordPolicy> {
        let mode = match self.mode {
            Mode::Choice => return None,
            Mode::SecondPassword => PasswordPolicyMode::SecondPassword,
            Mode::OnePassword => PasswordPolicyMode::OnePassword,
        };
        let (title, message) = self.texts()?;
        Some(PasswordPolicy {
            mode,
            action_needed: self.action_needed(),
            title,
            message,
        })
    }

    /// Hands Team vaults over as not writable while [`Rule::team_read_only`]: `configs` changed
    /// (`true`) or not. A vault's organisation is the list's, else its own signed record.
    pub fn limit_writes(&self, agent: &Agent, configs: &mut [LinkedVaultConfig]) -> bool {
        if !self.team_read_only() {
            return false;
        }
        let mut changed = false;
        for c in configs.iter_mut().filter(|c| c.writable) {
            let org = c.org.clone().or_else(|| org_of_key(agent, &c.key));
            if self.read_only_refusal(org.as_deref()).is_some() {
                c.writable = false;
                changed = true;
            }
        }
        changed
    }
}

/// The organisation of open shared vault `vault_id`: its own signed record, else the list's.
pub fn vault_org(agent: &Agent, vault_id: &str) -> Option<String> {
    let own = agent
        .shared_vault(vault_id)
        .and_then(|v| v.shared_info())
        .and_then(|i| i.org);
    own.or_else(|| {
        let key = agent
            .linked_status()
            .into_iter()
            .find(|s| s.vault.as_ref().is_some_and(|r| r.id == vault_id))?
            .key;
        agent
            .linked_configs()
            .into_iter()
            .find(|c| c.key == key)?
            .org
    })
}

fn org_of_key(agent: &Agent, key: &str) -> Option<String> {
    let id = agent
        .linked_status()
        .into_iter()
        .find(|s| s.key == key)?
        .vault?
        .id;
    agent.shared_vault(&id)?.shared_info()?.org
}

/// What each vault file opened with when last read, by its size and time (the list asks often).
static OWN_PASSWORD: Mutex<BTreeMap<PathBuf, (SystemTime, u64, bool)>> =
    Mutex::new(BTreeMap::new());

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Whether the vault file at `path` opens with its own password (not the Passyble password); `None` when unreadable.
fn opens_with_own_password(path: &Path) -> Option<bool> {
    let meta = std::fs::metadata(path).ok()?;
    let stamp = (meta.modified().ok()?, meta.len());
    if let Some((modified, len, own)) = guard(&OWN_PASSWORD).get(path) {
        if (*modified, *len) == stamp {
            return Some(*own);
        }
    }
    let access = pass_core::vault_file_access(std::fs::read(path).ok()?).ok()?;
    let own = access.kind == "password";
    guard(&OWN_PASSWORD).insert(path.to_path_buf(), (stamp.0, stamp.1, own));
    Some(own)
}

pub fn rule(app: &AppHandle) -> Rule {
    if crate::account::signed_in(app).is_none() {
        return Rule::default();
    }
    let state = app_state(app);
    let settings = state.settings();
    let orgs = settings.teams.map(|t| t.orgs).unwrap_or_default();
    if !orgs.iter().any(|o| o.kind == "team") {
        return Rule::default();
    }
    let open = state
        .agent()
        .and_then(|a| a.peek_vault())
        .map(|v| (v.account_link().is_none(), v.holds_sharing_keys()));
    let active = settings.active_vault.as_deref();
    let vaults: Vec<ListedVault> = settings
        .vaults
        .iter()
        .map(|v| match open {
            Some((own, keys)) if active == Some(v.id.as_str()) => ListedVault {
                id: v.id.clone(),
                name: v.name.clone(),
                own_password: Some(own),
                holds_keys: Some(keys),
            },
            _ => ListedVault {
                id: v.id.clone(),
                name: v.name.clone(),
                own_password: opens_with_own_password(&v.path),
                holds_keys: None,
            },
        })
        .collect();
    Rule::new(&orgs, &vaults, active)
}

/// `teams_overview` `password_policy`: `null` outside a Team, else the mode with its texts, the active vault, the
/// vaults with their own password and where sharing is off.
pub fn overview_json(app: &AppHandle, rule: &Rule, direct_org: Option<&str>) -> Value {
    if rule.teams.is_empty() {
        return Value::Null;
    }
    let (title, message) = rule.texts().unzip();
    let agent = app_state(app).agent();
    let blocked: Vec<String> = agent
        .as_ref()
        .map(|a| {
            a.open_vaults()
                .into_iter()
                .filter(|(r, _)| !r.home)
                .filter(|(r, _)| {
                    vault_org(a, &r.id).is_some_and(|o| rule.share_refusal(&o).is_some())
                })
                .map(|(r, _)| r.id)
                .collect()
        })
        .unwrap_or_default();
    let direct_off = direct_org.and_then(|o| rule.share_refusal(o));
    let sharing_note = rule.teams.iter().find_map(|(id, _)| rule.share_refusal(id));
    json!({
        "mode": rule.mode.as_str(),
        "action_needed": rule.action_needed(),
        "title": title,
        "message": message,
        "home": rule.scope.key_vault.as_ref().map(|(id, name, _)| json!({ "id": id, "name": name })),
        "own_password": rule.scope.counted.iter().map(|(id, name)| json!({ "id": id, "name": name })).collect::<Vec<_>>(),
        "blocked_vaults": blocked,
        "direct_share": direct_off.is_none(),
        "sharing_note": sharing_note,
    })
}

static REPORTED: Mutex<Option<(String, bool)>> = Mutex::new(None);

pub fn forget_report() {
    guard(&REPORTED).take();
}

/// Tells the account service whether this PC has a second-password vault, when that differs from last time.
/// Quiet; retried on the next refresh.
pub fn report(app: &AppHandle) {
    let Some(me) = crate::account::signed_in(app) else {
        return;
    };
    let rule = rule(app);
    let answer = rule.second_password();
    let last = guard(&REPORTED).clone();
    let said_yes = last.as_ref().is_some_and(|(id, on)| *id == me.id && *on);
    if last == Some((me.id.clone(), answer)) || (rule.teams.is_empty() && !said_yes) {
        return;
    }
    match crate::account::with_api(app, |api, _| api.report_second_password(answer)) {
        Ok(_) => *guard(&REPORTED) = Some((me.id, answer)),
        Err(e) => crate::applog::plog!("teams: second password report failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn team(id: &str, mode: &str, blocked: bool) -> CachedOrg {
        CachedOrg {
            id: id.into(),
            kind: "team".into(),
            name: "Acme".into(),
            role: "member".into(),
            policy: json!({ "password_mode": mode }).to_string(),
            sign_in_ok: true,
            sharing_blocked: blocked,
        }
    }

    fn family() -> CachedOrg {
        CachedOrg {
            id: "g_family".into(),
            kind: "family".into(),
            policy: json!({ "password_mode": "second_password" }).to_string(),
            ..Default::default()
        }
    }

    fn vault(id: &str, own: Option<bool>) -> ListedVault {
        ListedVault {
            id: id.into(),
            name: format!("{id} vault"),
            own_password: own,
            holds_keys: None,
        }
    }

    #[test]
    fn a_team_rule_covers_the_home_vault_and_every_vault_with_its_own_password() {
        let vaults = [
            ListedVault {
                holds_keys: Some(true),
                ..vault("home", Some(false))
            },
            vault("old", Some(true)),
            vault("gone", None),
        ];
        let scope = team_rule_vaults(&vaults, Some("home"));
        assert_eq!(
            scope.key_vault,
            Some(("home".to_string(), "home vault".to_string(), true))
        );
        assert_eq!(
            scope.counted,
            [("old".to_string(), "old vault".to_string())]
        );
        // Locked: the active vault is still the one that holds the Team's keys.
        let locked = team_rule_vaults(&[vault("home", Some(true))], Some("home"));
        assert_eq!(
            locked.key_vault.map(|(id, _, linked)| (id, linked)),
            Some(("home".into(), false))
        );
        // An open vault without the sharing keys carries no Team rule.
        let other = ListedVault {
            holds_keys: Some(false),
            ..vault("other", Some(false))
        };
        assert_eq!(team_rule_vaults(&[other], Some("other")).key_vault, None);
        assert_eq!(team_rule_vaults(&vaults, None).key_vault, None);
    }

    #[test]
    fn the_strictest_team_mode_wins_and_a_family_has_none() {
        assert_eq!(Mode::parse(None), Mode::Choice);
        assert_eq!(Mode::parse(Some("later_mode")), Mode::Choice);
        assert_eq!(org_mode(&family()), Mode::Choice);
        let vaults = [vault("home", Some(false))];
        let rule = Rule::new(
            &[
                team("g1", "one_password", false),
                team("g2", "second_password", false),
            ],
            &vaults,
            Some("home"),
        );
        assert_eq!(rule.mode, Mode::SecondPassword);
        let rule = Rule::new(
            &[
                team("g1", "choice", false),
                team("g2", "one_password", false),
            ],
            &vaults,
            Some("home"),
        );
        assert_eq!(rule.mode, Mode::OnePassword);
        // A missing key (an older service) reads as choice.
        let older = CachedOrg {
            policy: "{}".into(),
            ..team("g1", "", false)
        };
        assert_eq!(
            Rule::new(&[older], &vaults, Some("home")).mode,
            Mode::Choice
        );
        assert_eq!(
            Rule::new(&[family()], &vaults, Some("home")),
            Rule::default()
        );
    }

    #[test]
    fn a_second_password_is_counted_in_a_team_only() {
        let vaults = [
            vault("home", Some(false)),
            vault("old", Some(true)),
            vault("gone", None),
        ];
        let rule = Rule::new(&[team("g1", "choice", false)], &vaults, Some("home"));
        assert!(rule.second_password());
        assert_eq!(
            rule.scope.counted,
            [("old".to_string(), "old vault".to_string())]
        );
        assert!(!Rule::new(&[family()], &vaults, Some("home")).second_password());
        assert!(!Rule::new(&[], &vaults, Some("home")).second_password());
    }

    #[test]
    fn a_required_second_password_keeps_the_team_read_only_until_the_home_vault_has_one() {
        let orgs = [team("g1", "second_password", false)];
        let unmet = Rule::new(&orgs, &[vault("home", Some(false))], Some("home"));
        assert!(unmet.action_needed() && unmet.team_read_only());
        assert!(unmet.read_only_refusal(Some("g1")).is_some());
        assert!(
            unmet.read_only_refusal(Some("g_other")).is_none(),
            "not a Team of this account"
        );
        assert!(
            unmet.read_only_refusal(None).is_none(),
            "a self-hosted server's vault"
        );
        assert!(
            unmet.unlink_refusal("home", true).is_none(),
            "the home vault may take one now"
        );
        assert!(unmet.link_refusal("home").is_some());
        assert!(unmet.share_refusal("g1").is_some());
        assert!(unmet.agent_policy().unwrap().action_needed);
        let met = Rule::new(&orgs, &[vault("home", Some(true))], Some("home"));
        assert!(!met.action_needed() && !met.team_read_only());
        assert!(met.read_only_refusal(Some("g1")).is_none());
        assert!(
            met.share_refusal("g1").is_some(),
            "no sharing with a second password"
        );
        assert_eq!(
            met.agent_policy().unwrap().mode,
            PasswordPolicyMode::SecondPassword
        );
    }

    #[test]
    fn one_password_only_asks_each_vault_with_its_own_password_to_link() {
        let orgs = [team("g1", "one_password", false)];
        let rule = Rule::new(
            &orgs,
            &[vault("home", Some(false)), vault("old", Some(true))],
            Some("home"),
        );
        assert!(rule.action_needed() && !rule.team_read_only());
        assert!(
            rule.unlink_refusal("old", false).is_some(),
            "no separate password for any vault"
        );
        assert!(rule.link_refusal("home").is_none());
        assert!(
            rule.share_refusal("g1").is_some(),
            "still a vault with its own password"
        );
        let (_, message) = rule.texts().unwrap();
        assert!(message.contains("old vault"), "{message}");
        let done = Rule::new(&orgs, &[vault("home", Some(false))], Some("home"));
        assert!(!done.action_needed());
        assert!(done.share_refusal("g1").is_none());
    }

    #[test]
    fn sharing_follows_the_rule_and_the_service() {
        let vaults = [vault("home", Some(false))];
        let free = Rule::new(
            &[team("g1", "choice", false), family()],
            &vaults,
            Some("home"),
        );
        assert!(free.share_refusal("g1").is_none());
        assert!(
            free.share_refusal("g_family").is_none(),
            "a Family's shares are unchanged"
        );
        assert_eq!(free.agent_policy(), None);
        assert!(
            free.unlink_refusal("home", true).is_some(),
            "decision 6: the home vault keeps its link"
        );
        assert!(free.unlink_refusal("home", false).is_none());
        let blocked = Rule::new(&[team("g1", "choice", true)], &vaults, Some("home"));
        assert!(blocked.share_refusal("g1").is_some(), "the service says no");
    }
}
