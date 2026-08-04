use serde::de::DeserializeOwned;

pub(crate) fn deserialize<T>(body: &[u8]) -> Option<T>
where
    T: DeserializeOwned,
{
    if !has_valid_percent_encoding(body) {
        return None;
    }
    serde_urlencoded::from_bytes(body).ok()
}

fn has_valid_percent_encoding(body: &[u8]) -> bool {
    let mut index = 0;
    while index < body.len() {
        if body[index] == b'%' {
            if index + 2 >= body.len()
                || !is_ascii_hex(body[index + 1])
                || !is_ascii_hex(body[index + 2])
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn is_ascii_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

#[cfg(test)]
mod tests {
    use super::deserialize;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Form {
        value: String,
    }

    #[test]
    fn rejects_malformed_percent_encoding() {
        assert_eq!(deserialize::<Form>(b"value=%ZZ"), None);
        assert_eq!(deserialize::<Form>(b"value=%"), None);
    }

    #[test]
    fn preserves_valid_form_decoding() {
        assert_eq!(
            deserialize::<Form>(b"value=hello+world%21"),
            Some(Form {
                value: "hello world!".to_owned(),
            })
        );
    }
}
