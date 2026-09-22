use super::{AuthReservation, FailureDimension, LimiterDimension};

fn dimension(kind: FailureDimension, value: &str) -> LimiterDimension {
    (kind, value.to_owned())
}

#[test]
fn one_reserve_is_one_lease_even_when_it_covers_several_dimensions() {
    let reservation = AuthReservation::single(
        vec![
            dimension(FailureDimension::Account, "user@example.com"),
            dimension(FailureDimension::Ticket, "ticket"),
            dimension(FailureDimension::SourceIp, "203.0.113.5"),
        ],
        "shared-token".to_owned(),
    );

    assert_eq!(reservation.leases.len(), 1);
    assert_eq!(reservation.leases[0].token, "shared-token");
    assert_eq!(reservation.dimension_count(), 3);
    assert_eq!(
        reservation.dimensions(),
        vec![
            dimension(FailureDimension::Account, "user@example.com"),
            dimension(FailureDimension::Ticket, "ticket"),
            dimension(FailureDimension::SourceIp, "203.0.113.5"),
        ]
    );
}

#[test]
fn merge_keeps_each_reserve_token_instead_of_collapsing_them() {
    let source = AuthReservation::single(
        vec![dimension(FailureDimension::SourceIp, "203.0.113.5")],
        "source-token".to_owned(),
    );
    let account = AuthReservation::single(
        vec![dimension(FailureDimension::Account, "user@example.com")],
        "account-token".to_owned(),
    );

    let merged = source.merge(account);

    assert_eq!(merged.leases.len(), 2);
    assert_eq!(merged.leases[0].token, "source-token");
    assert_eq!(
        merged.leases[0].dimensions,
        vec![dimension(FailureDimension::SourceIp, "203.0.113.5")]
    );
    assert_eq!(merged.leases[1].token, "account-token");
    assert_eq!(
        merged.leases[1].dimensions,
        vec![dimension(FailureDimension::Account, "user@example.com")]
    );
    assert_eq!(merged.dimension_count(), 2);
}

#[test]
fn empty_reserve_has_no_lease_and_is_not_a_denial() {
    let allowed = AuthReservation::single(Vec::new(), "unused-token".to_owned());
    assert!(allowed.leases.is_empty());
    assert!(allowed.is_empty());
    assert!(!allowed.is_denied());
    assert_eq!(allowed.dimension_count(), 0);

    let denied = AuthReservation::denied();
    assert!(denied.leases.is_empty());
    assert!(denied.is_denied());
}
