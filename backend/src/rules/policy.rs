use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]

pub struct Policy {
    /// Pairs for Rule 7 that must not be active simultaneously.
    pub pairs: Option<Vec<[String; 2]>>,
    /// Memory ranges and access policies for Rule 10.
    pub memory_areas: Option<Vec<MemoryArea>>,
    /// Target platform, e.g. "S7" or "Codesys". Used to gate platform-specific rules.
    pub platform: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryArea {
    /// Address range, e.g. "%MW100-%MW200"
    pub address: String,
    /// Access policy: "ReadOnly" | "ReadWrite"
    pub access: String,
}

/// Example policy JSON embedded as a constant (not in comments).

pub const EXAMPLE_POLICY_JSON: &str = r#"{
  "pairs": [
    ["Motor_Fwd", "Motor_Rev"],
    ["Valve_Open", "Valve_Close"]
  ],
  "memory_areas": [
    { "address": "%MW100-%MW200", "access": "ReadOnly" },
    { "address": "%M50-%M80",     "access": "ReadWrite" },
  "platform": "S7"
  ]
}"#;

/// Parse a policy JSON string into a Policy structure. Returns
/// `Ok(policy)` if parsing succeeds or `Err(msg)` if the JSON is invalid.
///
/// The default [`Policy`] is returned when fields are missing, but if
/// the JSON is malformed, an error is returned with details from the
/// underlying serde parser. Consumers can use this to surface errors
/// back to the user instead of failing silently.
pub fn parse_policy_from_text(s: &str) -> Result<Policy, String> {
    serde_json::from_str::<Policy>(s).map_err(|e| format!("Invalid policy JSON: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_policy_json_parses() {
        let p: Policy = serde_json::from_str(EXAMPLE_POLICY_JSON).unwrap();
        assert!(p.pairs.as_ref().unwrap().len() >= 1);
        assert!(p.memory_areas.as_ref().unwrap().len() >= 1);
    }
}
