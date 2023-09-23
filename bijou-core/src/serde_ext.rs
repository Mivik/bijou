use serde::de::Visitor;

struct BytesVisitor<const N: usize>();
impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a byte array of length {N}")
    }
}

pub mod base64 {
    use super::BytesVisitor;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        let base64 = STANDARD.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let base64 = String::deserialize(d)?;
        let decoded = STANDARD
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)?;

        <[u8; N]>::try_from(decoded).map_err(|decoded| {
            serde::de::Error::invalid_length(decoded.len(), &BytesVisitor::<N>())
        })
    }
}
