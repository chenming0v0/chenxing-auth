pub type AdminId = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    Owner,
    Operator,
    Auditor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminPermission {
    ManageUsers,
    ManageClients,
    RotateKeys,
    ReadAudit,
    ManageSettings,
}

impl AdminRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "operator" => Some(Self::Operator),
            "auditor" => Some(Self::Auditor),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
        }
    }

    pub const fn allows(self, permission: AdminPermission) -> bool {
        match self {
            Self::Owner => true,
            Self::Operator => matches!(permission, AdminPermission::ManageClients),
            Self::Auditor => matches!(permission, AdminPermission::ReadAudit),
        }
    }
}
