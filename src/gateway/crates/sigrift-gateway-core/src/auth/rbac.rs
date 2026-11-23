//! Unified role-based access control — 6-level hierarchy matching Python's dependencies.py.
//!
//! Hierarchy (ascending): SENSOR < NODE < VIEWER < ANALYST < ADMIN < KEYMASTER

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Role {
    Sensor = 0,
    Node = 1,
    Viewer = 2,
    Analyst = 3,
    Admin = 4,
    Keymaster = 5,
}

/// Error returned when a string names no known [`Role`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRole;

impl std::fmt::Display for UnknownRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unknown role")
    }
}

impl std::error::Error for UnknownRole {}

impl std::str::FromStr for Role {
    type Err = UnknownRole;

    /// Parse from string (case-insensitive).
    /// Matches Python: `Role[role_str.upper()]`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "SENSOR" => Ok(Role::Sensor),
            "NODE" => Ok(Role::Node),
            "VIEWER" => Ok(Role::Viewer),
            "ANALYST" => Ok(Role::Analyst),
            "ADMIN" => Ok(Role::Admin),
            "KEYMASTER" => Ok(Role::Keymaster),
            _ => Err(UnknownRole),
        }
    }
}

impl Role {
    /// Lowercase string for DB storage (matches Python convention).
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Sensor => "sensor",
            Role::Node => "node",
            Role::Viewer => "viewer",
            Role::Analyst => "analyst",
            Role::Admin => "admin",
            Role::Keymaster => "keymaster",
        }
    }

    /// Returns true if this role meets or exceeds the minimum required level.
    pub fn has_at_least(&self, min: Role) -> bool {
        (*self as u8) >= (min as u8)
    }

    /// Role ceiling (contract K5): may a caller holding this role create a
    /// key or user with role `target`, or assign `target` to one? Never
    /// above the caller's own role, and KEYMASTER only by a KEYMASTER.
    pub fn may_grant(&self, target: Role) -> bool {
        match target {
            Role::Keymaster => *self == Role::Keymaster,
            _ => self.has_at_least(target),
        }
    }

    /// Role ceiling (contract K5) for existing principals: may a caller
    /// holding this role change, rotate, reset, disable or revoke a key or
    /// user that currently holds `target`? Only one it could have granted —
    /// otherwise an admin could take over a KEYMASTER account by resetting
    /// its password or rotating its key.
    pub fn may_manage(&self, target: Role) -> bool {
        self.may_grant(target)
    }

    /// Parse a role stored in the database for a ceiling check. An unknown
    /// value counts as KEYMASTER, so only a KEYMASTER may touch it.
    pub fn parse_stored_for_ceiling(stored: &str) -> Role {
        stored.parse().unwrap_or(Role::Keymaster)
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_ordering() {
        assert!(Role::Sensor < Role::Node);
        assert!(Role::Node < Role::Viewer);
        assert!(Role::Viewer < Role::Analyst);
        assert!(Role::Analyst < Role::Admin);
        assert!(Role::Admin < Role::Keymaster);
    }

    #[test]
    fn test_from_str_case_insensitive() {
        assert_eq!("viewer".parse(), Ok(Role::Viewer));
        assert_eq!("ADMIN".parse(), Ok(Role::Admin));
        assert_eq!("Keymaster".parse(), Ok(Role::Keymaster));
        assert_eq!("Analyst".parse(), Ok(Role::Analyst));
        assert_eq!("sensor".parse(), Ok(Role::Sensor));
        assert_eq!("NODE".parse(), Ok(Role::Node));
        assert_eq!("invalid".parse::<Role>(), Err(UnknownRole));
        assert_eq!("".parse::<Role>(), Err(UnknownRole));
    }

    #[test]
    fn test_as_str_lowercase() {
        assert_eq!(Role::Sensor.as_str(), "sensor");
        assert_eq!(Role::Admin.as_str(), "admin");
        assert_eq!(Role::Keymaster.as_str(), "keymaster");
    }

    #[test]
    fn test_has_at_least() {
        assert!(Role::Admin.has_at_least(Role::Viewer));
        assert!(Role::Admin.has_at_least(Role::Admin));
        assert!(!Role::Viewer.has_at_least(Role::Admin));
        assert!(Role::Keymaster.has_at_least(Role::Keymaster));
        assert!(Role::Sensor.has_at_least(Role::Sensor));
        assert!(!Role::Sensor.has_at_least(Role::Node));
    }

    #[test]
    fn role_ceilings() {
        let all = [
            Role::Sensor,
            Role::Node,
            Role::Viewer,
            Role::Analyst,
            Role::Admin,
            Role::Keymaster,
        ];
        for caller in all {
            for target in all {
                let expected = if target == Role::Keymaster {
                    caller == Role::Keymaster
                } else {
                    caller >= target
                };
                assert_eq!(caller.may_grant(target), expected, "{caller} → {target}");
                assert_eq!(caller.may_manage(target), expected, "{caller} → {target}");
                assert_eq!(
                    caller.has_at_least(target),
                    caller >= target,
                    "{caller} >= {target}"
                );
            }
        }
        assert!(!Role::Admin.may_grant(Role::Keymaster));
        assert!(Role::Admin.may_grant(Role::Admin));
        assert_eq!(Role::parse_stored_for_ceiling("analyst"), Role::Analyst);
        assert_eq!(Role::parse_stored_for_ceiling("bogus"), Role::Keymaster);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Role::Admin), "admin");
        assert_eq!(format!("{}", Role::Keymaster), "keymaster");
    }

    const ALL: [Role; 6] = [
        Role::Sensor,
        Role::Node,
        Role::Viewer,
        Role::Analyst,
        Role::Admin,
        Role::Keymaster,
    ];

    /// Deny by default: only a string whose Unicode uppercase is exactly a
    /// role name parses (see `case_mapped_spellings_parse_like_the_bridge`).
    /// Padded, numeric, combined or look-alike values that do not case-map
    /// to a role name (Kelvin sign, fullwidth or Cyrillic letters, combining
    /// marks, dotted capital I, zero-width space) name no role, and the
    /// error does not echo the rejected input back to the caller.
    #[test]
    fn unknown_role_strings_are_rejected() {
        for s in [
            "\u{212a}eymaster",
            "\u{ff21}dmin",
            "\u{430}dmin",
            "admi\u{301}n",
            "ADM\u{130}N",
            "admin\u{200b}",
            " admin",
            "admin ",
            "admin\n",
            "\tviewer",
            "ad min",
            "admin\0",
            "administrator",
            "admins",
            "root",
            "superuser",
            "owner",
            "0",
            "4",
            "5",
            "admin,keymaster",
            "Role::Admin",
        ] {
            assert_eq!(s.parse::<Role>(), Err(UnknownRole), "{s:?}");
        }
        assert_eq!(UnknownRole.to_string(), "unknown role");
    }

    /// An unknown role stored in the database fails closed for ceiling
    /// checks: it ranks as KEYMASTER, so no caller below KEYMASTER may
    /// manage the account, while known roles keep their own level.
    #[test]
    fn unknown_stored_role_is_manageable_only_by_keymaster() {
        for stored in [
            "",
            "superuser",
            "root",
            " admin",
            "admin ",
            "4",
            "\u{430}dmin",
            "\u{212a}eymaster",
        ] {
            let effective = Role::parse_stored_for_ceiling(stored);
            assert_eq!(effective, Role::Keymaster, "{stored:?}");
            for caller in ALL {
                assert_eq!(
                    caller.may_manage(effective),
                    caller == Role::Keymaster,
                    "{caller} managing {stored:?}"
                );
            }
        }
        for role in ALL {
            assert_eq!(Role::parse_stored_for_ceiling(role.as_str()), role);
            assert_eq!(
                Role::parse_stored_for_ceiling(&role.as_str().to_uppercase()),
                role
            );
        }
    }

    /// The stored (lowercase) form of every role parses back to the same
    /// role, so a stored role never silently changes level on a re-read.
    #[test]
    fn role_names_round_trip() {
        for role in ALL {
            assert_eq!(role.as_str().parse::<Role>(), Ok(role));
            assert_eq!(role.to_string(), role.as_str());
        }
    }

    /// Decision, pinned: parsing uses the full Unicode uppercase mapping,
    /// as the bridge does (`Role[name.upper()]`, `_role_from_name`), so a
    /// spelling that case-maps to a role name is that role: dotless i
    /// (U+0131), long s (U+017F) and the "st" ligature (U+FB06). Each maps
    /// only to the role it spells, never higher, and ranks as that role for
    /// ceiling checks too (matching the access a stored value of it gets in
    /// the bridge and the gateway). The handlers store only the canonical name
    /// of the parsed role (`admin_user_handler`'s
    /// `keymaster_ceiling_holds_for_any_spelling`).
    #[test]
    fn case_mapped_spellings_parse_like_the_bridge() {
        for (spelling, role) in [
            ("adm\u{131}n", Role::Admin),
            ("ADM\u{131}N", Role::Admin),
            ("keyma\u{17f}ter", Role::Keymaster),
            ("keyma\u{fb06}er", Role::Keymaster),
            ("\u{17f}ensor", Role::Sensor),
            ("v\u{131}ewer", Role::Viewer),
        ] {
            assert_eq!(spelling.parse::<Role>(), Ok(role), "{spelling:?}");
            assert_eq!(
                Role::parse_stored_for_ceiling(spelling),
                role,
                "{spelling:?}"
            );
        }
    }
}
