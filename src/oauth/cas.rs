//! Stable Redis CAS identity for OAuth credentials.
//!
//! Rolling upgrades used to break consumption: Lua compared the complete
//! reserialized JSON, so an older instance that dropped unknown fields could
//! not consume a payload written by a newer instance. CAS now matches only
//! the natural key plus `cas_revision`. Missing revisions are 0 so in-flight
//! legacy payloads stay consumable. Revision 0 is omitted on write so mixed
//! deployments that still compare full JSON keep seeing the old layout.

/// `cas_revision = 0` is the implicit generation of every legacy payload.
pub(crate) fn is_zero_cas_revision(revision: &u64) -> bool {
    *revision == 0
}

pub(crate) fn next_cas_revision(current: u64) -> u64 {
    current.saturating_add(1)
}

/// Shared Lua: compare natural key + `cas_revision`. Unknown fields are ignored.
macro_rules! cas_identity_lua {
    () => {
        r#"
local function cas_revision(obj)
    local rev = obj['cas_revision']
    if rev == nil then
        return 0
    end
    return tonumber(rev) or 0
end

local function same_cas_identity(current_json, expected_json, id_field)
    local current = cjson.decode(current_json)
    local expected = cjson.decode(expected_json)
    if type(current) ~= 'table' or type(expected) ~= 'table' then
        return false
    end
    if current[id_field] ~= expected[id_field] then
        return false
    end
    return cas_revision(current) == cas_revision(expected)
end
"#
    };
}
pub(crate) use cas_identity_lua;

#[cfg(test)]
mod tests {
    use super::{is_zero_cas_revision, next_cas_revision};

    #[test]
    fn zero_is_the_legacy_revision() {
        assert!(is_zero_cas_revision(&0));
        assert!(!is_zero_cas_revision(&1));
        assert_eq!(next_cas_revision(0), 1);
        assert_eq!(next_cas_revision(u64::MAX), u64::MAX);
    }
}
