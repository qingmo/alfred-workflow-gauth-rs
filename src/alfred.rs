//! Alfred Script Filter JSON feedback. See Alfred docs: an object `{ "items": [...] }`.

use serde::Serialize;

#[derive(Serialize)]
pub struct Feedback {
    pub items: Vec<Item>,
}

#[derive(Serialize)]
pub struct Item {
    pub title: String,
    pub subtitle: String,
    pub arg: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Icon>,
}

#[derive(Serialize)]
pub struct Icon {
    pub path: String,
}

impl Item {
    /// An actionable account row: pressing Enter sends `code` (the `arg`).
    pub fn account(name: &str, code: &str) -> Self {
        Item {
            title: name.to_string(),
            subtitle: format!("Post {code} at cursor"),
            arg: code.to_string(),
            valid: true,
            icon: Some(Icon { path: "icon.png".into() }),
        }
    }

    /// A non-actionable informational row (warning / time remaining).
    pub fn message(title: &str, subtitle: &str, icon: Option<&str>) -> Self {
        Item {
            title: title.to_string(),
            subtitle: subtitle.to_string(),
            arg: String::new(),
            valid: false,
            icon: icon.map(|p| Icon { path: p.to_string() }),
        }
    }
}

/// Serialize feedback to the JSON string Alfred expects on stdout.
pub fn render(feedback: &Feedback) -> String {
    serde_json::to_string(feedback).expect("feedback serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_item_is_valid_with_code_arg() {
        let item = Item::account("aws", "123456");
        assert!(item.valid);
        assert_eq!(item.arg, "123456");
        assert_eq!(item.subtitle, "Post 123456 at cursor");
    }

    #[test]
    fn message_item_is_not_valid() {
        let item = Item::message("Account not found", "no match", Some("warning.png"));
        assert!(!item.valid);
        assert_eq!(item.arg, "");
    }

    #[test]
    fn render_emits_items_object() {
        let fb = Feedback { items: vec![Item::account("aws", "123456")] };
        let json = render(&fb);
        assert!(json.contains("\"items\""));
        assert!(json.contains("\"arg\":\"123456\""));
        assert!(json.contains("\"valid\":true"));
    }
}
