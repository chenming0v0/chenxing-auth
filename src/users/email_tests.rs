use super::{EmailAddress, EmailError, MAX_EMAIL_LENGTH, canonical_domain, is_valid_email};

fn parse(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("{raw:?} must parse: {error}"))
}

/// Issue #302 的核心回归：Unicode 域名的所有等价书写必须收敛到同一个匹配值。
///
/// 补丁前 `to_ascii_lowercase` 只动 ASCII 字节，`ÉXAMPLE.COM` 会留下
/// `Éxample.com`，于是同一个邮箱按不同书写就成了不同账号。
#[test]
fn unicode_domain_variants_share_one_canonical_value() {
    let canonical = parse("user@éxample.com").into_canonical();
    for variant in [
        "user@ÉXAMPLE.COM",
        "user@Éxample.com",
        "user@éxample.com",
        // 已编码的 Punycode 与它的 Unicode 原形等价。
        "user@xn--xample-9ua.com",
        "user@XN--XAMPLE-9UA.COM",
        // NFD：E + COMBINING ACUTE ACCENT。UTS-46 归一后与 NFC 形态一致。
        "user@e\u{0301}xample.com",
    ] {
        assert_eq!(
            parse(variant).canonical(),
            canonical,
            "{variant} must canonicalize to the same value"
        );
    }
}

/// 展示值的域名同样是 ASCII 形态：它会进入邮件头与管理台列表。
#[test]
fn display_value_uses_the_ascii_domain() {
    let email = parse("User@ÉXAMPLE.COM");
    assert_eq!(email.display(), "User@xn--xample-9ua.com");
    assert_eq!(email.canonical(), "user@xn--xample-9ua.com");
}

/// 展示值保留本地部分的大小写，匹配值不保留。
///
/// 这是"展示与匹配分离"的可观察证据：补丁前两者都被压成小写，用户的邮箱拼写
/// 在没有必要的地方被改写。
#[test]
fn display_preserves_local_case_while_canonical_folds_it() {
    let email = parse("  John.Doe@Example.COM  ");
    assert_eq!(email.display(), "John.Doe@example.com");
    assert_eq!(email.canonical(), "john.doe@example.com");
    assert_eq!(email.canonical_local_part(), "john.doe");
    assert_eq!(email.canonical_domain(), "example.com");
}

/// 本地部分的 ASCII 大小写折叠是唯一的本地部分规则。
#[test]
fn ascii_local_case_variants_collide_but_nothing_else_is_stripped() {
    assert_eq!(
        parse("USER@example.com").canonical(),
        parse("user@example.com").canonical()
    );
    // 加号别名不剥离：provider 特定语义不能在认证中枢里被统一猜测。
    assert_ne!(
        parse("user+tag@example.com").canonical(),
        parse("user@example.com").canonical()
    );
    assert_eq!(
        parse("user+tag@example.com").canonical_local_part(),
        "user+tag"
    );
    // 点号同样不剥离。
    assert_ne!(
        parse("u.ser@example.com").canonical(),
        parse("user@example.com").canonical()
    );
}

/// 非 ASCII 本地部分不做大小写折叠或 NFC 归一。
///
/// 保守方向：两种书写被当成两个不同邮箱（拒绝合并），而不是替 SMTPUTF8 的
/// 字节敏感语义做猜测。
#[test]
fn non_ascii_local_part_is_left_untouched() {
    let email = parse("Ünser@example.com");
    assert_eq!(email.display(), "Ünser@example.com");
    // 只有 ASCII 字节被折叠，`Ü` 原样保留。
    assert_eq!(email.canonical(), "Ünser@example.com");
}

#[test]
fn domain_root_dot_is_rejected_to_keep_one_canonical_form() {
    // `example.com.` 与 `example.com` 在 DNS 上等价，接受它就等于允许同一域名
    // 有两个匹配值。
    assert_eq!(
        EmailAddress::parse("user@example.com."),
        Err(EmailError::InvalidDomain)
    );
}

#[test]
fn structurally_invalid_addresses_are_rejected() {
    let oversized_label = format!("user@{}.example", "a".repeat(64));
    for (raw, expected) in [
        ("", EmailError::Empty),
        ("   ", EmailError::Empty),
        ("user", EmailError::MalformedStructure),
        ("user@a@example.com", EmailError::MalformedStructure),
        ("@example.com", EmailError::EmptyLocalPart),
        ("user@", EmailError::InvalidDomain),
        // 单标签域名：保留补丁前"域名必须含点"的边界。
        ("user@localhost", EmailError::InvalidDomain),
        ("user@.example.com", EmailError::InvalidDomain),
        ("user@example..com", EmailError::InvalidDomain),
        // `xn--` 标签解码后含 UTS-46 不允许的字符（U+2488 映射出点号）。
        // 这类标签必须被拒绝：接受它会让匹配值依赖解码实现的细节。
        ("user@xn--a-ecp.example", EmailError::InvalidDomain),
        // 标签超过 63 字节。
        (oversized_label.as_str(), EmailError::InvalidDomain),
        ("us er@example.com", EmailError::ForbiddenCharacter),
        ("user\u{0009}@example.com", EmailError::ForbiddenCharacter),
        ("user\u{0000}@example.com", EmailError::ForbiddenCharacter),
        // WHATWG forbidden domain code point。
        ("user@exa<mple.com", EmailError::InvalidDomain),
        ("user@exa mple.com", EmailError::ForbiddenCharacter),
    ] {
        assert_eq!(EmailAddress::parse(raw), Err(expected), "{raw:?}");
    }
}

/// 下划线域名继续放行。
///
/// `AsciiDenyList::STD3` 会拒绝它，而补丁前的校验是放行的；用 STD3 会把存量
/// 账号直接锁死，属于破坏用户空间。
#[test]
fn underscore_domains_remain_accepted_for_backward_compatibility() {
    assert_eq!(
        parse("user@a_b.example").canonical(),
        "user@a_b.example",
        "existing accounts on underscore hosts must keep working"
    );
}

#[test]
fn length_bound_is_enforced_before_and_after_punycode_expansion() {
    let domain = "@example.com";
    let local = "a".repeat(MAX_EMAIL_LENGTH - domain.len());
    let at_bound = format!("{local}{domain}");
    assert_eq!(at_bound.chars().count(), MAX_EMAIL_LENGTH);
    assert_eq!(
        parse(&at_bound).canonical().chars().count(),
        MAX_EMAIL_LENGTH
    );

    assert_eq!(
        EmailAddress::parse(&format!("a{at_bound}")),
        Err(EmailError::TooLong)
    );

    // Punycode 展开后越界：编码前是合法长度，编码后不是。
    // `é` 所在标签编码成 `xn--...`，长度显著增长。
    let unicode_local = "b".repeat(MAX_EMAIL_LENGTH - "@éxample.com".chars().count());
    let before_encoding = format!("{unicode_local}@éxample.com");
    assert_eq!(before_encoding.chars().count(), MAX_EMAIL_LENGTH);
    assert_eq!(
        EmailAddress::parse(&before_encoding),
        Err(EmailError::TooLong),
        "the bound must be re-checked after punycode expansion"
    );
}

#[test]
fn canonical_domain_matches_the_address_domain() {
    assert_eq!(
        canonical_domain("ÉXAMPLE.COM").as_deref(),
        Ok("xn--xample-9ua.com")
    );
    assert_eq!(
        canonical_domain("ÉXAMPLE.COM").as_deref(),
        Ok(parse("user@éxample.com").canonical_domain())
    );
    assert_eq!(canonical_domain(""), Err(EmailError::InvalidDomain));
    assert_eq!(
        canonical_domain("localhost"),
        Err(EmailError::InvalidDomain)
    );
}

#[test]
fn is_valid_email_agrees_with_parse() {
    for raw in ["user@example.com", "user@éxample.com", "USER@EXAMPLE.COM"] {
        assert!(is_valid_email(raw), "{raw}");
    }
    for raw in ["", "user", "user@localhost", "user @example.com"] {
        assert!(!is_valid_email(raw), "{raw}");
    }
}

/// 规范化必须是幂等的：把匹配值再喂回 `parse` 得到同一个匹配值。
///
/// 迁移回填、缓存键和限流维度都隐含这一点——不幂等的规范化会让"同一个账号"
/// 在不同调用路径上算出不同的键。
#[test]
fn canonicalization_is_idempotent() {
    for raw in [
        "User@ÉXAMPLE.COM",
        "user@xn--xample-9ua.com",
        "user+tag@a_b.example",
        "Ünser@example.com",
    ] {
        let once = parse(raw).into_canonical();
        let twice = parse(&once).into_canonical();
        assert_eq!(once, twice, "{raw}");
    }
}

#[test]
fn debug_output_exposes_both_values_for_drift_diagnosis() {
    let rendered = format!("{:?}", parse("User@Example.com"));
    assert!(rendered.contains("User@example.com"), "{rendered}");
    assert!(rendered.contains("user@example.com"), "{rendered}");
}

/// 相等性是"同一个邮箱"，按匹配值判定，不比较展示值。
///
/// 若按全字段判定，`User@example.com == user@example.com` 会是 false——那正是本
/// Issue 要消除的假阴性，只是从数据库唯一索引搬到了内存比较里。
#[test]
fn equality_means_same_mailbox_not_same_spelling() {
    let mixed = parse("User@ÉXAMPLE.COM");
    let lower = parse("user@xn--xample-9ua.com");

    assert_eq!(mixed, lower);
    assert_ne!(mixed.display(), lower.display());
    // 不同邮箱仍然不相等。
    assert_ne!(mixed, parse("other@xn--xample-9ua.com"));
}

/// `Hash` 必须与 `PartialEq` 一致：相等的值同哈希。
///
/// 不一致会让 `HashSet` 同时处于"包含"和"查不到"两种状态。
#[test]
fn hash_agrees_with_equality() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(parse("User@ÉXAMPLE.COM"));

    assert!(set.contains(&parse("user@xn--xample-9ua.com")));
    // 重复插入等价书写不增加基数。
    set.insert(parse("USER@éxample.com"));
    assert_eq!(set.len(), 1);
}
